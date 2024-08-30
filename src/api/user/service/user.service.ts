import { DocumentClient } from 'aws-sdk/clients/dynamodb';
import {
	BadRequestException,
	HttpException,
	HttpStatus,
	Injectable,
	UnauthorizedException,
} from '@nestjs/common';
import * as AWS from 'aws-sdk';
import { v4 as uuidv4 } from 'uuid';
import * as otpGenerator from 'otp-generator';
import * as bcrypt from 'bcrypt';
import * as dynamoose from 'dynamoose';
import { Model } from 'dynamoose/dist/Model';
import { CognitoService } from '../cognito/cognito.service';
import { AuthChangePasswordUserDto } from '../dto/auth-change-password-user.dto';
import { AuthConfirmPasswordUserDto } from '../dto/auth-confirm-password-user.dto';
import { AuthForgotPasswordUserDto } from '../dto/auth-forgot-password-user.dto';
import { CreateUserDto } from '../dto/create-user.dto';
import { CreateUserResponse } from '../dto/responses';
import { SignInDto } from '../dto/signin.dto';
import { UpdateUserDto } from '../dto/update-user.dto';
import { User } from '../entities/user.entity';
import { Otp } from '../../auth/entities/otp.entity';
import { UserSchema } from '../entities/user.schema';
import { OtpSchema } from '../../auth/entities/otp.schema';
import { GetUsersDto } from '../dto/get-user.dto';
import { CreateOtpRequestDto } from '../../auth/dto/create-otp-request.dto';
import { CreateOtpResponseDto } from '../../auth/dto/create-otp-response.dto';
import { VerifyOtpDto } from '../dto/forgotPassword.dto';
import { generateStrongPassword } from '../../../utils/helpers/generateRandomPassword';
import { generateUniqueId } from '../../../utils/helpers/generateUniqueId';
import { SqsService } from '../sqs/sqs.service';
import { UpdateStatusUserDto } from '../dto/update-status-user.dto';
import { Attempt } from '../../auth/entities/auth-attempt.entity';
import { AuthAttemptSchema } from '../../auth/entities/auth-attempt.schema';
import { convertToCamelCase } from '../../../utils/helpers/convertCamelCase';
import * as Sentry from '@sentry/nestjs';
import { RoleService } from '../../role/service/role.service';
import { ProviderService } from '../../provider/service/provider.service';

@Injectable()
export class UserService {
	private dbInstance: Model<User>;
	private dbOtpInstance: Model<Otp>;
	private dbAttemptInstance: Model<Attempt>;
	private cognitoService: CognitoService;
	private cognito: AWS.CognitoIdentityServiceProvider;
	private roleService: RoleService;
	private providerService: ProviderService;

	constructor(private readonly sqsService: SqsService) {
		this.dbInstance = dynamoose.model<User>('Users', UserSchema);
		this.dbOtpInstance = dynamoose.model<Otp>('Otps', OtpSchema);
		this.dbAttemptInstance = dynamoose.model<Attempt>(
			'Attempts',
			AuthAttemptSchema
		);
		this.roleService = new RoleService(this.providerService);
		this.cognitoService = new CognitoService();
		this.cognito = new AWS.CognitoIdentityServiceProvider({
			region: process.env.AWS_REGION,
		});
	}

	async generateOtp(
		createOtpRequestDto: CreateOtpRequestDto
	): Promise<CreateOtpResponseDto> {
		const { email, token } = createOtpRequestDto;

		const existingOtpEmail = await this.dbOtpInstance
			.query('Email')
			.eq(email)
			.exec();

		if (existingOtpEmail.count > 0) {
			throw new Error(`OTP already exist`);
		}

		let otp = otpGenerator.generate(6, {
			upperCaseAlphabets: false,
			lowerCaseAlphabets: false,
			specialChars: false,
		});

		let existingOtp = await this.dbOtpInstance.query('Otp').eq(otp).exec();

		while (existingOtp.count > 0) {
			otp = otpGenerator.generate(6, {
				upperCaseAlphabets: false,
			});
			existingOtp = await this.dbOtpInstance.query('Otp').eq(otp).exec();
		}

		const ttl = Math.floor(Date.now() / 1000) + 60 * 5;

		const otpPayload = { Email: email, Otp: otp, Token: token, Ttl: ttl };
		await this.dbOtpInstance.create(otpPayload);

		return {
			success: true,
			message: 'OTP sent successfully',
			otp,
		};
	}

	async listAccessLevels(roleId: string) {
		const docClient = new DocumentClient();
		const params = {
			TableName: 'Roles',
			Key: { Id: roleId },
			ProjectionExpression: 'Modules',
		};

		const result = await docClient.get(params).promise();
		return result.Item?.Modules || {};
	}

	async verifyOtp(verifyOtp: VerifyOtpDto) {
		try {
			const otpRecord = await this.dbOtpInstance
				.query('Email')
				.eq(verifyOtp?.email)
				.exec();

			if (!otpRecord?.[0]?.Otp) {
				throw new HttpException(
					'Invalid or expired OTP',
					HttpStatus.UNAUTHORIZED
				);
			}

			const existingToken = await this.dbOtpInstance
				.query('Otp')
				.eq(verifyOtp?.otp)
				.attributes(['Token'])
				.exec();

			await this.dbOtpInstance.delete({
				Email: verifyOtp?.email,
				Otp: verifyOtp?.otp,
			});

			const userFind = await this.findOneByEmail(verifyOtp.email);

			await this.dbInstance.update({
				Id: userFind?.id,
				State: 3,
				Active: true,
			});

			if (userFind?.Type == 'WALLET') {
				await this.dbInstance.update({
					Id: userFind?.id,
					First: false,
				});
			}

			const user = await this.findOneByEmail(verifyOtp.email);

			let accessLevel = {};
			if (user?.roleId !== 'EMPTY') {
				accessLevel = await this.listAccessLevels(user?.roleId);
			}

			user.accessLevel = accessLevel;

			delete user.passwordHash;
			delete user.otpTimestamp;

			return {
				user,
				token: existingToken?.[0]?.Token,
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	async create(createUserDto: CreateUserDto) {
		try {
			const {
				email,
				firstName,
				lastName,
				type,
				phone,
				mfaEnabled,
				mfaType,
				roleId,
				serviceProviderId,
				termsConditions,
				privacyPolicy,
				passwordHash,
			} = createUserDto;

			// Generate password and hash it
			const password =
				type === 'WALLET' ? passwordHash : generateStrongPassword(11);
			const hashedPassword = await bcrypt.hash(password, 8);

			// Generate random id
			let uniqueIdValue;

			uniqueIdValue = generateUniqueId(type);

			// Verificar la unicidad del ID
			const verifyUnique = await this.findOne(uniqueIdValue);

			while (verifyUnique?.Id) {
				uniqueIdValue = generateUniqueId(type);
			}

			// Create user in Cognito
			await this.cognitoService.createUser(email, password, email);

			// Prepare user data for DynamoDB
			const userData = {
				Id: uniqueIdValue,
				FirstName: firstName,
				LastName: lastName,
				Phone: phone,
				Email: email.toLowerCase(),
				PasswordHash: hashedPassword,
				MfaEnabled: mfaEnabled,
				ServiceProviderId: type === 'PROVIDER' ? serviceProviderId : 'EMPTY',
				MfaType: mfaType,
				RoleId: type === 'WALLET' ? 'EMPTY' : roleId,
				Type: type,
				State: 0,
				Active: true,
				TermsConditions: termsConditions,
				PrivacyPolicy: privacyPolicy,
			};

			await this.dbInstance.create(userData);

			let tokenValue = '';

			if (type == 'WALLET') {
				const valueAuth = {
					email: email.toLowerCase(),
					password: passwordHash,
				};
				tokenValue = await this.authenticateUser(valueAuth);
			}

			const result = await this.generateOtp({ email, token: tokenValue });

			await this.sendOtpOrPasswordMessage(
				type,
				email,
				firstName,
				lastName,
				result.otp,
				password
			);

			delete result.otp;
			return convertToCamelCase(result);
		} catch (error) {
			Sentry.captureException(error);
			throw new Error('Failed to create user. Please try again later.');
		}
	}

	async sendOtpOrPasswordMessage(
		type: string,
		email: string,
		firstName = '',
		lastName: string,
		otp: string,
		password: string
	) {
		const event =
			type === 'WALLET' ? 'WALLET_USER_CREATED' : 'FIRST_PASSWORD_GENERATED';
		const otpOrPassword = type === 'WALLET' ? otp : password;
		const username = firstName + (lastName ? ' ' + lastName : '');
		const sqsMessage = {
			event,
			email,
			username,
			value: otpOrPassword,
		};

		await this.sqsService.sendMessage(process.env.SQS_QUEUE_URL, sqsMessage);
	}

	async findOne(id: string) {
		try {
			return await convertToCamelCase(this.dbInstance.get({ Id: id }));
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error retrieving user: ${error.message}`);
		}
	}

	async findOneByEmailValidationAttributes(
		email: string
	): Promise<User | null> {
		try {
			const users = await this.dbInstance
				.query('Email')
				.eq(email)
				.attributes(['Id', 'Email'])
				.exec();
			return users[0];
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error retrieving user: ${error.message}`);
		}
	}

	async findOneByEmailAllAttributes(email: string): Promise<User | null> {
		try {
			const users = await this.dbInstance
				.query('Email')
				.eq(email)
				.attributes([
					'Id',
					'type',
					'Email',
					'First',
					'LastLogin',
					'Username',
					'MfaEnabled',
					'MfaType',
				])
				.exec();
			return convertToCamelCase(users[0]);
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error retrieving user: ${error.message}`);
		}
	}

	async findOneByEmail(email: string) {
		try {
			const users = await this.dbInstance.query('Email').eq(email).exec();
			return convertToCamelCase(users[0]);
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error retrieving user: ${error.message}`);
		}
	}

	async update(id: string, updateUserDto: UpdateUserDto) {
		try {
			return convertToCamelCase(
				await this.dbInstance.update({
					Id: id,
					FirstName: updateUserDto?.firstName,
					LastName: updateUserDto?.lastName,
					Email: updateUserDto?.email,
					ServiceProviderId: updateUserDto?.serviceProviderId,
					MfaEnabled: updateUserDto?.mfaEnabled,
					MfaType: updateUserDto?.mfaType,
					RoleId: updateUserDto?.roleId,
					TermsConditions: updateUserDto?.termsConditions,
					PrivacyPolicy: updateUserDto?.privacyPolicy,
					SocialSecurityNumber: updateUserDto?.socialSecurityNumber,
					IdentificationType: updateUserDto?.identificationType,
					IdentificationNumber: updateUserDto?.identificationNumber,
					Country: updateUserDto?.country,
					StateLocation: updateUserDto?.stateLocation,
					City: updateUserDto?.city,
					ZipCode: updateUserDto?.zipCode,
					Address: updateUserDto?.address,
					DateOfBirth: updateUserDto?.dateOfBirth,
					Avatar: updateUserDto?.avatar,
				})
			);
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error updating user: ${error.message}`);
		}
	}

	async remove(id: string): Promise<void> {
		const user = await this.findOne(id);
		if (!user) {
			throw new Error('User not found in database');
		}
		await convertToCamelCase(
			this.dbInstance.update({
				Id: id,
				Active: false,
			})
		);
	}

	mapUserToCreateUserResponse(user: User): CreateUserResponse {
		return {
			id: user.Id,
			firstName: user.FirstName,
			lastName: user.LastName,
			email: user.Email,
			phone: user.Phone,
			type: user.Type,
			roleId: user.RoleId,
			active: user.PasswordHash !== '',
			state: user.State,
			first: user.First,
			serviceProviderId: user.ServiceProviderId,
			lastLogin: user.LastLogin,
			termsConditions: user.TermsConditions,
			privacyPolicy: user.PrivacyPolicy,
		};
	}

	private async deletePreviousOtp(email: string) {
		const otpRecord = await this.dbOtpInstance.scan({ Email: email }).exec();
		if (otpRecord && otpRecord.length > 0) {
			await this.dbOtpInstance.delete({
				Email: otpRecord[0].Email,
				Otp: otpRecord[0].Otp,
			});
		}
	}

	private async authenticateUser(signinDto: SignInDto) {
		const authResult = await this.cognitoService.authenticateUser(
			signinDto.email.toLowerCase(),
			signinDto.password
		);
		const token = authResult.AuthenticationResult?.AccessToken;

		if (!token) {
			throw new BadRequestException('Invalid credentials');
		}
		return token;
	}

	private async logAttempt(
		Id: string,
		Email: string,
		Status: 'success' | 'failure',
		Section: string
	) {
		const logPayload = {
			Id,
			Email,
			Section,
			Status,
		};
		await this.dbAttemptInstance.create(logPayload);
	}

	private async sendOtpNotification(foundUser: any, otp: string) {
		foundUser.firstName = foundUser.firstName || '';
		const sqsMessage = {
			event: 'LOGGED_IN',
			email: foundUser.email,
			username:
				foundUser.firstName +
				(foundUser.lastName ? ' ' + foundUser.lastName : ''),
			value: otp,
		};
		await this.sqsService.sendMessage(process.env.SQS_QUEUE_URL, sqsMessage);
	}

	async signin(signinDto: SignInDto) {
		const transactionId = uuidv4();
		try {
			await this.deletePreviousOtp(signinDto.email.toLowerCase());
			const foundUser = await this.findOneByEmail(
				signinDto.email.toLowerCase()
			);
			const token = await this.authenticateUser(signinDto);

			const otpResult = await this.generateOtp({
				email: signinDto.email.toLowerCase(),
				token,
			});

			await this.logAttempt(
				transactionId,
				signinDto.email.toLowerCase(),
				'success',
				'login'
			);

			await this.sendOtpNotification(foundUser, otpResult.otp);

			delete otpResult.otp;

			return convertToCamelCase({
				...otpResult,
			});
		} catch (error) {
			Sentry.captureException(error);
			await this.logAttempt(transactionId, signinDto.email, 'failure', 'login');
			throw new BadRequestException('Invalid credentials');
		}
	}

	async changeUserPassword(
		authChangePasswordUserDto: AuthChangePasswordUserDto
	) {
		const { token, currentPassword, newPassword } = authChangePasswordUserDto;

		const user = await this.getUserInfo(token);

		const userFind = await this.findOneByEmail(
			user?.UserAttributes?.[0]?.Value
		);

		await this.dbInstance.update({
			Id: userFind?.id,
			First: false,
		});

		await this.cognitoService.changePassword(
			token?.split(' ')?.[1],
			currentPassword,
			newPassword
		);
	}

	async forgotUserPassword(
		authForgotPasswordUserDto: AuthForgotPasswordUserDto
	): Promise<string> {
		const { email } = authForgotPasswordUserDto;
		return await convertToCamelCase(this.cognitoService.forgotPassword(email));
	}

	async confirmUserPassword(
		authConfirmPasswordUserDto: AuthConfirmPasswordUserDto
	) {
		const { email, confirmationCode, newPassword } = authConfirmPasswordUserDto;

		await convertToCamelCase(
			this.cognitoService.confirmForgotPassword(
				email,
				confirmationCode,
				newPassword
			)
		);
	}

	async getUsersByType(getUsersDto: GetUsersDto): Promise<{
		users: User[];
		currentPage: number;
		total: number;
		totalPages: number;
	}> {
		const {
			type = 'WALLET',
			email,
			serviceProviderId,
			id,
			page = 1,
			items = 10,
		} = getUsersDto;

		let query = this.dbInstance.query('Type').eq(type);

		if (email) {
			query = query.and().filter('Email').eq(email);
		}

		if (id) {
			query = query.and().filter('Id').eq(id);
		}

		if (serviceProviderId) {
			query = query.and().filter('ServiceProviderId').eq(serviceProviderId);
		}

		query.attributes([
			'Id',
			'Type',
			'Email',
			'First',
			'FirstName',
			'LastName',
			'Phone',
			'ServiceProviderId',
			'RoleId',
			'Active',
			'State',
			'MfaEnabled',
			'MfaType',
		]);

		// Execute the query
		const result = await query.exec();
		let users = convertToCamelCase(result);

		// Apply regex search client-side if 'search' is provided
		if (getUsersDto?.search) {
			const regex = new RegExp(getUsersDto?.search, 'i'); // 'i' for case-insensitive
			users = users.filter(
				user =>
					regex.test(user.email) ||
					regex.test(user.firstName) ||
					regex.test(user.lastName) ||
					regex.test(user.id) ||
					regex.test(`${user.firstName} ${user.lastName}`)
			);
		}

		const roleIds = [...new Set(users.map(user => user.roleId))];
		const roles = await this.roleService.getRolesByIds(roleIds);

		users = users?.map(user => {
			const role = roles?.find(
				r => typeof r !== 'string' && r?.Id === user.roleId
			);
			user.roleName = role ? role?.Name : 'Not found';
			return user;
		});

		const total = users.length;
		const offset = (Number(page) - 1) * Number(items);
		const paginatedUsers = users.slice(offset, offset + Number(items));
		const totalPages = Math.ceil(total / Number(items));

		return {
			users: paginatedUsers,
			currentPage: Number(page),
			total,
			totalPages,
		};
	}

	async verifySignUp(verifyOtp: VerifyOtpDto) {
		try {
			const otpRecord = await this.dbOtpInstance.scan(verifyOtp).exec();

			if (!otpRecord || otpRecord.count === 0) {
				throw new HttpException(
					'Invalid or expired OTP',
					HttpStatus.UNAUTHORIZED
				);
			}

			await this.dbOtpInstance.delete({
				Email: verifyOtp?.email,
				Otp: verifyOtp?.otp,
			});

			const userFind = await this.dbInstance
				.query('Email')
				.eq(verifyOtp?.email)
				.exec();

			if (userFind?.length === 0) {
				throw new Error('User not found.');
			}

			const userId = userFind?.[0].Id;

			await convertToCamelCase(
				this.dbInstance.update({
					Id: userId,
					State: 3,
					First: false,
					Active: true,
				})
			);

			const user = await this.findOneByEmail(verifyOtp.email);

			delete user.PasswordHash;
			delete user.OtpTimestamp;
			delete user.Id;

			return {
				user,
				verified: true,
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	async getUserInfo(authHeader: string) {
		if (!authHeader || !authHeader.startsWith('Bearer ')) {
			throw new UnauthorizedException('No token provided');
		}

		const accessToken = authHeader.split(' ')[1];

		try {
			const params = {
				AccessToken: accessToken,
			};

			const userData = await this.cognito.getUser(params).promise();
			return userData;
		} catch (error) {
			Sentry.captureException(error);
			throw new UnauthorizedException('Invalid access token');
		}
	}

	async changeStatusUser(
		updateUserDto: UpdateStatusUserDto
	): Promise<User | null> {
		try {
			const user = await this.findOneByEmail(updateUserDto?.email);

			await this.dbInstance.update({
				Id: user?.id,
				Active: updateUserDto?.active,
			});

			const userUpd = await this.findOneByEmail(updateUserDto?.email);

			delete userUpd.passwordHash;
			delete userUpd.otpTimestamp;

			return userUpd;
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error updating user: ${error.message}`);
		}
	}
	async resendOtp(user): Promise<void> {
		const foundOtp = await this.dbOtpInstance
			.query('Email')
			.eq(user.email)
			.exec();
		if (foundOtp.count === 0) {
			throw new Error(`OTP does not exist`);
		}
		await this.sendOtpNotification(user, foundOtp[0].Otp);
	}

	async revokeTokenLogout(token: string) {
		await convertToCamelCase(
			this.cognitoService.revokeToken(token?.split(' ')?.[1])
		);
	}

	async validateAccessMiddleware(token: string, path: string, method: string) {
		const userCognito = await this.getUserInfo(token);
		const user = await this.findOneByEmail(
			userCognito?.UserAttributes?.[0]?.Value
		);
		const userRoleId = user.roleId;

		const requestedModuleId = this.getModuleIdFromPath(path);
		const requiredMethod = method;

		const role = await this.roleService.getRoleInfo(userRoleId);

		const userAccessLevel = role?.Modules[requestedModuleId];

		const accessMap = {
			GET: 8,
			POST: 4,
			PUT: 2,
			PATCH: 1,
			DELETE: 1,
		};

		const requiredAccess = accessMap[requiredMethod];

		return {
			requiredAccess,
			userAccessLevel,
		};
	}

	private getModuleIdFromPath(path: string): string {
		const moduleIdMap = {
			'/api/v1/users': 'U783',
			'/api/v1/roles': 'R949',
			'/api/v1/providers': 'SP95',
			'/api/v1/wallets': 'W325',
		};

		const normalizedPath = path.split('/').slice(0, 4).join('/');

		return moduleIdMap[normalizedPath] || '';
	}
}
