import { DocumentClient } from 'aws-sdk/clients/dynamodb';
import {
	BadRequestException,
	HttpException,
	HttpStatus,
	Injectable,
} from '@nestjs/common';
import * as AWS from 'aws-sdk';
import { v4 as uuidv4 } from 'uuid';
import { createHmac } from 'crypto';
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
import { errorCodes } from '../../../utils/constants';
import {
	S3Client,
	DeleteObjectCommand,
	PutObjectCommand,
} from '@aws-sdk/client-s3';
import axios from 'axios';
import { createSignature } from '../../../utils/helpers/signatureHelper';

@Injectable()
export class UserService {
	private dbInstance: Model<User>;
	private dbOtpInstance: Model<Otp>;
	private dbAttemptInstance: Model<Attempt>;
	private cognitoService: CognitoService;
	private cognito: AWS.CognitoIdentityServiceProvider;
	private roleService: RoleService;
	private providerService: ProviderService;
	private apiUrl;
	private appToken;
	private appSecretKey;

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
		this.appToken = process.env.SUMSUB_APP_TOKEN;
		this.appSecretKey = process.env.SUMSUB_SECRET_TOKEN;
		this.apiUrl = 'https://api.sumsub.com';
	}

	async generateOtp(
		createOtpRequestDto: CreateOtpRequestDto
	): Promise<CreateOtpResponseDto> {
		const { email, token, refreshToken } = createOtpRequestDto;

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

		const otpPayload = {
			Email: email,
			Otp: otp,
			Token: token,
			RefreshToken: refreshToken,
			Ttl: ttl,
		};
		await this.dbOtpInstance.create(otpPayload);

		return {
			success: true,
			message: 'OTP sent successfully',
			otp,
		};
	}

	async getUserById(userId: string) {
		const docClient = new DocumentClient();
		const params = {
			TableName: 'Users',
			Key: { Id: userId },
		};

		try {
			const result = await docClient.get(params).promise();
			return convertToCamelCase(result?.Item);
		} catch (error) {
			Sentry.captureException(error);
			return {
				statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
				customCode: 'WGE0137',
			};
		}
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

	async listAccessLevelsPlatformModules(roleId: string) {
		const docClient = new DocumentClient();
		const params = {
			TableName: 'Roles',
			Key: { Id: roleId },
			ProjectionExpression: 'PlatformModules',
		};

		const result = await docClient.get(params).promise();
		return result.Item?.PlatformModules || {};
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

			if (otpRecord?.[0]?.Otp !== verifyOtp?.otp) {
				throw new HttpException('Incorrect OTP', HttpStatus.UNAUTHORIZED);
			}

			const existingToken = await this.dbOtpInstance
				.query('Otp')
				.eq(verifyOtp?.otp)
				.attributes(['Token', 'RefreshToken'])
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
				refresToken: existingToken?.[0]?.RefreshToken,
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	async create(createUserDto: CreateUserDto, user?: string) {
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

			let providerId = 'EMPTY';
			if (type !== 'WALLET') {
				const userConverted = user as unknown as {
					Name: string;
					Value: string;
				}[];
				const userEmail = userConverted?.[0]?.Value;

				const userFind = await this.findOneByEmail(userEmail);

				providerId =
					userFind && userFind?.type == 'PROVIDER'
						? userFind?.serviceProviderId
						: userFind && userFind?.type == 'WALLET'
						? 'EMPTY'
						: serviceProviderId;
			}

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
				ServiceProviderId: providerId ? providerId : 'EMPTY',
				MfaType: mfaType,
				RoleId: type === 'WALLET' ? 'EMPTY' : roleId,
				Type: type,
				State: 0,
				Active: true,
				TermsConditions: termsConditions,
				PrivacyPolicy: privacyPolicy,
			};

			await this.dbInstance.create(userData);

			let userToken;

			if (type == 'WALLET') {
				const valueAuth = {
					email: email.toLowerCase(),
					password: passwordHash,
				};
				userToken = await this.authenticateUser(valueAuth);
			}

			const accessToken = userToken?.AccessToken as string;

			const result = await this.generateOtp({ email, token: accessToken });

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

	async refreshToken(token: string, email: string) {
		try {
			const user = await this.getUserInfoByEmail(email);
			const newToken = await this.cognitoService.refreshToken(
				token,
				user?.Username
			);

			return newToken;
		} catch (error) {
			Sentry.captureException(error);
			return new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
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
			return convertToCamelCase(await this.dbInstance.get({ Id: id }));
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

	async findOneByPhone(phone: string) {
		try {
			const users = await this.dbInstance.query('Phone').eq(phone).exec();
			return convertToCamelCase(users[0]);
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error retrieving user: ${error.message}`);
		}
	}

	async findOneById(id: string) {
		try {
			const users = await this.dbInstance.query('Id').eq(id).exec();
			return convertToCamelCase(users[0]);
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error retrieving user: ${error.message}`);
		}
	}

	async update(id: string, updateUserDto: UpdateUserDto) {
		try {
			const userFind = await this.findOneById(id);

			if (!userFind) {
				throw new Error(`User with ID ${id} not found.`);
			}

			const updatedUser = {
				...userFind,
				...updateUserDto,
				dateOfBirth: updateUserDto.dateOfBirth
					? new Date(updateUserDto.dateOfBirth)
					: userFind.dateOfBirth,
			};

			await this.dbInstance.update({
				Id: id,
				FirstName: updatedUser.firstName,
				LastName: updatedUser.lastName,
				Email: updatedUser.email,
				Phone: updatedUser.phone,
				ServiceProviderId: updatedUser.serviceProviderId,
				MfaEnabled: updatedUser.mfaEnabled,
				MfaType: updatedUser.mfaType,
				RoleId: updatedUser.roleId,
				TermsConditions: updatedUser.termsConditions,
				PrivacyPolicy: updatedUser.privacyPolicy,
				SocialSecurityNumber: updatedUser.socialSecurityNumber,
				IdentificationType: updatedUser.identificationType,
				IdentificationNumber: updatedUser.identificationNumber,
				Country: updatedUser.country,
				StateLocation: updatedUser.stateLocation,
				City: updatedUser.city,
				ZipCode: updatedUser.zipCode,
				Address: updatedUser.address,
				DateOfBirth: updatedUser.dateOfBirth,
				Avatar: updatedUser.avatar,
			});

			const userInfo = await this.getUserById(id);

			return convertToCamelCase(userInfo);
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error updating user: ${error.message}`);
		}
	}

	async toggleFirst(id: string) {
		const user = await this.findOne(id);

		if (!user) {
			throw new HttpException(
				{
					customCode: 'WGE0002',
					...errorCodes.WGE0002,
				},
				HttpStatus.NOT_FOUND
			);
		}
		user.first = !user.first;
		const updatedUser = await this.dbInstance.update(id, {
			First: user.first,
		});
		return convertToCamelCase(updatedUser);
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
		const token = authResult.AuthenticationResult;

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
			const accessToken = token?.AccessToken as string;
			const refreshToken = token?.RefreshToken as string;

			const otpResult = await this.generateOtp({
				email: signinDto.email.toLowerCase(),
				token: accessToken,
				refreshToken: refreshToken,
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
		return await convertToCamelCase(
			this.cognitoService.forgotPassword(email?.toLowerCase())
		);
	}

	async confirmUserPassword(
		authConfirmPasswordUserDto: AuthConfirmPasswordUserDto
	): Promise<any> {
		const { email, confirmationCode, newPassword } = authConfirmPasswordUserDto;

		const confirmPassword = await this.cognitoService.confirmForgotPassword(
			email?.toLowerCase(),
			confirmationCode,
			newPassword
		);

		if (confirmPassword?.customCode) {
			return {
				customCode: 'WGE0005',
			};
		}

		return await convertToCamelCase(confirmPassword);
	}

	async getUsersByType(
		getUsersDto: GetUsersDto,
		userRequest: unknown
	): Promise<{
		users: User[];
		currentPage: number;
		total: number;
		totalPages: number;
	}> {
		const {
			type = 'PROVIDER',
			email,
			serviceProviderId,
			id,
			page = 1,
			items = 10,
			orderBy = 'firstName',
			ascending = true,
		} = getUsersDto;

		let providerId = null;

		const userConverted = userRequest as unknown as {
			Name: string;
			Value: string;
		}[];
		const emailRequest = userConverted[0]?.Value; // Safely extract Value

		const userDb = await this.dbInstance.scan('Email').eq(emailRequest).exec();

		let query = this.dbInstance.query('Type').eq(type);

		if (email) {
			query = query.and().filter('Email').eq(email);
		}

		if (id) {
			query = query.and().filter('Id').eq(id);
		}

		if (serviceProviderId) {
			query = query.and().filter('ServiceProviderId').eq(serviceProviderId);
			providerId = serviceProviderId;
		}

		if (
			!serviceProviderId &&
			userDb[0].ServiceProviderId &&
			userDb[0].Type === 'PROVIDER'
		) {
			query = query
				.and()
				.filter('ServiceProviderId')
				.eq(userDb[0].ServiceProviderId);
			providerId = userDb[0].ServiceProviderId;
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
			'ContactUser',
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

		if (type === 'PROVIDER') {
			users = users.filter(
				(user: { email: string; serviceProviderId: string }) =>
					user.email !== emailRequest && user.serviceProviderId === providerId
			);
		} else {
			users = users.filter(
				(user: { email: string }) => user.email !== emailRequest
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

		users.sort((a, b) => {
			if (a.active !== b.active) {
				return a.active ? -1 : 1;
			}
			if (a[orderBy] === b[orderBy]) {
				return 0;
			}
			return ascending
				? a[orderBy] > b[orderBy]
					? 1
					: -1
				: a[orderBy] < b[orderBy]
				? 1
				: -1;
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
			throw new HttpException(
				{
					statusCode: HttpStatus.UNAUTHORIZED,
					customCode: 'WGE0021',
				},
				HttpStatus.UNAUTHORIZED
			);
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
			throw new HttpException(
				{
					statusCode: HttpStatus.UNAUTHORIZED,
					customCode: 'WGE0021',
				},
				HttpStatus.UNAUTHORIZED
			);
		}
	}

	async getUserInfoByEmail(email: string) {
		try {
			await this.findOneByEmail(email);
			const userData = await this.cognitoService.getUserInfoByEmail(email);
			return userData;
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					statusCode: HttpStatus.UNAUTHORIZED,
					customCode: 'WGE0021',
				},
				HttpStatus.UNAUTHORIZED
			);
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

	async validateAccess(token: string, path: string, method: string) {
		const userCognito = await this.getUserInfo(token);
		const user = await this.findOneByEmail(
			userCognito?.UserAttributes?.[0]?.Value
		);

		if (!user) {
			return {
				statusCode: HttpStatus.NOT_FOUND,
				customCode: 'WGE0002',
			};
		}

		const userRoleId = user.roleId;
		const requestedModuleId = this.getModuleIdFromPath(path);
		const requiredMethod = method;
		const role = await this.roleService.getRoleInfo(userRoleId);

		if (user?.type === 'PLATFORM' && requestedModuleId == 'SP95') {
			return { hasAccess: true };
		}

		const userAccessLevel = role?.Modules[requestedModuleId];
		const accessMap = {
			GET: 8,
			POST: 4,
			PUT: 2,
			PATCH: 1,
			DELETE: 1,
		};

		const requiredAccess = accessMap[requiredMethod];

		if (
			userAccessLevel < 8 ||
			((userAccessLevel & requiredAccess) !== requiredAccess &&
				user.type !== 'WALLET')
		) {
			return {
				statusCode: HttpStatus.UNAUTHORIZED,
				customCode: 'WGE0038',
			};
		}

		return { hasAccess: true };
	}

	getModuleIdFromPath(path: string): string {
		const moduleIdMap = {
			'/api/v1/users': 'U783',
			'/api/v1/roles': 'R949',
			'/api/v1/providers': 'SP95',
			'/api/v1/wallets': 'W325',
			'/api/v1/settings': 'SE37',
			'/api/v1/payments': 'PY38',
		};

		const normalizedPath = path.split('/').slice(0, 4).join('/');
		return moduleIdMap[normalizedPath] || '';
	}

	// async uploadImage(id: string, file: Express.Multer.File) {
	// 	try {
	// 		if (file) {
	// 			const fileExtension = file.originalname.split('.').pop().toLowerCase();
	// 			const allowedExtensions = ['jpg', 'jpeg', 'svg', 'png'];
	//
	// 			if (!allowedExtensions.includes(fileExtension)) {
	// 				throw new HttpException(
	// 					{
	// 						statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
	// 						customCode: 'WGE0043',
	// 						customMessage: errorCodes.WGE0043?.description,
	// 						customMessageEs: errorCodes.WGE0043?.descriptionEs,
	// 					},
	// 					HttpStatus.INTERNAL_SERVER_ERROR
	// 				);
	// 			}
	//
	// 			const fileName = `${uuidv4()}.${fileExtension}`;
	// 			const filePath = `service-providers/${id}/${fileName}`;
	//
	// 			const user = await this.dbInstance.get({ Id: id });
	// 			const currentImageUrl = user?.Picture;
	//
	// 			if (currentImageUrl) {
	// 				const currentImageKey = currentImageUrl.split('.com/')[1];
	// 				await this.s3
	// 					.deleteObject({
	// 						Bucket: process.env.AWS_S3_BUCKET_NAME,
	// 						Key: currentImageKey,
	// 					})
	// 					.promise();
	// 			}
	//
	// 			const AwsImage = await this.s3
	// 				.upload({
	// 					Bucket: process.env.AWS_S3_BUCKET_NAME,
	// 					Key: filePath,
	// 					Body: file.buffer,
	// 					ContentType: file.mimetype,
	// 					ACL: 'public-read',
	// 				})
	// 				.promise();
	//
	// 			const updatedProvider = {
	// 				Id: id,
	// 				Picture: AwsImage.Location,
	// 			};
	//
	// 			return this.dbInstance.update(updatedProvider);
	// 		}
	// 	} catch (error) {
	// 		Sentry.captureException(error);
	// 		console.log('error', error);
	// 		throw new HttpException(
	// 			{
	// 				statusCode: HttpStatus.FORBIDDEN,
	// 				customCode: 'WGE0050',
	// 				customMessage: errorCodes?.WGE0050?.description,
	// 				customMessageEs: errorCodes.WGE0050?.descriptionEs,
	// 			},
	// 			HttpStatus.INTERNAL_SERVER_ERROR
	// 		);
	// 	}
	// }

	async uploadImage(id: string, file: Express.Multer.File) {
		try {
			if (file) {
				const fileExtension = file.originalname.split('.').pop().toLowerCase();
				const allowedExtensions = ['jpg', 'jpeg', 'svg', 'png'];

				if (!allowedExtensions.includes(fileExtension)) {
					throw new HttpException(
						{
							statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
							customCode: 'WGE0043',
							customMessage: errorCodes.WGE0043?.description,
							customMessageEs: errorCodes.WGE0043?.descriptionEs,
						},
						HttpStatus.INTERNAL_SERVER_ERROR
					);
				}

				const fileName = `${uuidv4()}.${fileExtension}`;
				const filePath = `users/${id}/${fileName}`;

				const user = await this.dbInstance.get({ Id: id });
				const currentImageUrl = user?.Picture;

				const s3Client = new S3Client({
					region: process.env.AWS_REGION,
					credentials: {
						accessKeyId: process.env.AWS_KEY_ID,
						secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
					},
				});

				if (currentImageUrl) {
					const currentImageKey = currentImageUrl.split('.com/')[1];

					const deleteCommand = new DeleteObjectCommand({
						Bucket: process.env.AWS_S3_BUCKET_NAME,
						Key: currentImageKey,
					});

					await s3Client.send(deleteCommand);
				}

				const uploadCommand = new PutObjectCommand({
					Bucket: process.env.AWS_S3_BUCKET_NAME,
					Key: filePath,
					Body: file.buffer,
					ContentType: file.mimetype,
					ACL: 'public-read',
				});

				await s3Client.send(uploadCommand);

				const updateUser = {
					Id: id,
					Picture: `https://${process.env.AWS_S3_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${filePath}`,
				};

				return this.dbInstance.update(updateUser);
			}
		} catch (error) {
			Sentry.captureException(error);
			console.log('error', error);
			throw new HttpException(
				{
					statusCode: HttpStatus.FORBIDDEN,
					customCode: 'WGE0050',
					customMessage: errorCodes?.WGE0050?.description,
					customMessageEs: errorCodes.WGE0050?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	async toggleContact(id: string) {
		const user = await this.findOne(id);

		if (!user) {
			throw new HttpException(
				{
					customCode: 'WGE0002',
					...errorCodes.WGE0002,
				},
				HttpStatus.NOT_FOUND
			);
		}
		user.contactUser = !user.contactUser;
		const updatedUser = await this.dbInstance.update(id, {
			ContactUser: user.contactUser,
		});
		return convertToCamelCase(updatedUser);
	}

	async getAccessToken(
		userId: string,
		levelName: string,
		headerSignature
	): Promise<any> {
		const body = {
			ttlInSecs: 600,
			userId,
			levelName,
		};

		try {
			const response = await axios.post(
				this.apiUrl + '/resources/accessTokens/sdk',
				body,
				{ headers: headerSignature }
			);
			return response.data;
		} catch (error) {
			throw new HttpException(
				error.response?.data || 'Error fetching access token',
				error.response?.status || HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	async validateDataToSumsub(data) {
		return data === 'GREEN';
	}

	private async setSumSubHeaders(
		path: string,
		method: string,
		body = ''
	): Promise<Record<string, string>> {
		const timestamp = Math.floor(Date.now() / 1000).toString();
		const signatureData = `${timestamp}${method}${path}${body}`;

		const hmac = createHmac('sha256', this.appSecretKey);
		const signature = hmac.update(signatureData).digest('hex');

		return {
			Accept: 'application/json',
			'Content-Type': 'application/json',
			'X-App-Access-Ts': timestamp,
			'X-App-Access-Sig': signature,
			'X-App-Token': this.appToken,
		};
	}

	async getDataFromSumsub(applicantId: string) {
		const path = `/resources/applicants/${applicantId}/one`;
		const url = `${this.apiUrl}${path}`;
		const headers = await this.setSumSubHeaders(path, 'GET');

		try {
			const response = await axios.get(url, { headers });
			return response.data;
		} catch (error) {
			throw new Error(
				`Error al obtener los datos: ${
					error.response?.statusText || error.message
				}`
			);
		}
	}

	async kycFlow(userInput) {
		const isValid = await this.validateDataToSumsub(
			userInput?.reviewResult?.reviewAnswer
		);
		const sumsubData = await this.getDataFromSumsub(userInput?.applicantId);

		if (!sumsubData?.externalUserId) {
			return;
		}

		if (isValid) {
			const result = await this.dbInstance.update({
				Id: sumsubData?.externalUserId,
				State: 2,
				IdentificationType: sumsubData?.info?.idDocs?.[0]?.idDocType,
				IdentificationNumber: sumsubData?.info?.idDocs?.[0]?.number,
				FirstName: sumsubData?.info?.firstName,
				LastName: sumsubData?.info?.lastName,
				DateOfBirth: new Date(sumsubData?.info?.dob),
			});

			return convertToCamelCase(result);
		} else {
			const result = await this.dbInstance.update({
				Id: sumsubData?.externalUserId,
				State: 1,
			});

			return convertToCamelCase(result);
		}
	}
}
