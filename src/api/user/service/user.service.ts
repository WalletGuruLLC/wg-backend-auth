import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import {
	AuthenticationDetails,
	CognitoUser,
	CognitoUserPool,
} from 'amazon-cognito-identity-js';
import * as otpGenerator from 'otp-generator';
import * as bcrypt from 'bcrypt';
import * as dynamoose from 'dynamoose';
import { Model } from 'dynamoose/dist/Model';
import { CognitoService } from '../cognito/cognito.service';
import { AuthChangePasswordUserDto } from '../dto/auth-change-password-user.dto';
import { AuthConfirmPasswordUserDto } from '../dto/auth-confirm-password-user.dto';
import { AuthForgotPasswordUserDto } from '../dto/auth-forgot-password-user.dto';
import { CreateUserDto } from '../dto/create-user.dto';
import { CreateUserResponse, getUsersResponse } from '../dto/responses';
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

@Injectable()
export class UserService {
	private dbInstance: Model<User>;
	private dbOtpInstance: Model<Otp>;
	private cognitoService: CognitoService;
	private userPool: CognitoUserPool;

	constructor(private readonly sqsService: SqsService) {
		const tableName = 'users';
		this.dbInstance = dynamoose.model<User>(tableName, UserSchema);
		this.dbOtpInstance = dynamoose.model<Otp>('otps', OtpSchema);
		this.cognitoService = new CognitoService();
		this.userPool = new CognitoUserPool({
			UserPoolId: process.env.COGNITO_USER_POOL_ID,
			ClientId: process.env.COGNITO_CLIENT_ID,
		});
	}

	async generateOtp(
		createOtpRequestDto: CreateOtpRequestDto
	): Promise<CreateOtpResponseDto> {
		const { email } = createOtpRequestDto;

		const existingOtpEmail = await this.dbOtpInstance
			.query('email')
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

		let existingOtp = await this.dbOtpInstance.query('otp').eq(otp).exec();

		while (existingOtp.count > 0) {
			otp = otpGenerator.generate(6, {
				upperCaseAlphabets: false,
			});
			existingOtp = await this.dbOtpInstance.query('otp').eq(otp).exec();
		}

		const otpPayload = { email, otp };
		await this.dbOtpInstance.create(otpPayload);

		return {
			success: true,
			message: 'OTP sent successfully',
			otp,
		};
	}

	async verifyOtp(verifyOtp: VerifyOtpDto) {
		try {
			const otpRecord = await this.dbOtpInstance.scan(verifyOtp).exec();

			if (!otpRecord || otpRecord.count === 0) {
				throw new HttpException(
					'Invalid or expired OTP',
					HttpStatus.UNAUTHORIZED
				);
			}

			await this.dbOtpInstance.delete({
				email: verifyOtp?.email,
				otp: verifyOtp?.otp,
			});

			const user = await this.findOneByEmail(verifyOtp.email);

			delete user.PasswordHash;
			delete user.OtpTimestamp;

			return {
				user,
				verified: true,
			};
		} catch (error) {
			console.error(error.message);
			throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	async create(createUserDto: CreateUserDto) {
		try {
			const {
				email,
				id,
				firstName,
				lastName,
				type,
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
				type === 'WALLET' ? passwordHash : generateStrongPassword();
			const hashedPassword = await bcrypt.hash(password, 8);

			// Generate random id
			let uniqueIdValue;

			uniqueIdValue = generateUniqueId(type);

			// Verificar la unicidad del ID
			const verifyUnique = await this.findOne(uniqueIdValue);

			while (verifyUnique) {
				uniqueIdValue = generateUniqueId(type);
			}

			// Create user in Cognito
			const cognitoPromise = this.cognitoService.createUser(
				email,
				password,
				email
			);

			// Prepare user data for DynamoDB
			const userData = {
				Id: id,
				FirstName: firstName,
				LastName: lastName,
				Email: email,
				PasswordHash: hashedPassword,
				MfaEnabled: mfaEnabled,
				ServiceProviderId: type === 'WALLET' ? 'EMPTY' : serviceProviderId,
				MfaType: mfaType,
				RoleId: type === 'WALLET' ? 'EMPTY' : roleId,
				Type: type,
				State: 0,
				Active: false,
				TermsConditions: termsConditions,
				PrivacyPolicy: privacyPolicy,
			};

			// Create user in DynamoDB
			const dbPromise = this.dbInstance.create(userData);

			// Wait for both Cognito and DynamoDB operations to complete
			await Promise.all([cognitoPromise, dbPromise]);

			// Generate and return OTP
			return this.generateOtp({ email });
		} catch (error) {
			console.error('Error creating user:', error.message);
			throw new Error('Failed to create user. Please try again later.');
		}
	}

	async findOne(id: string): Promise<User | null> {
		try {
			return await this.dbInstance.get({ Id: id });
		} catch (error) {
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
			return users[0];
		} catch (error) {
			throw new Error(`Error retrieving user: ${error.message}`);
		}
	}

	async findOneByEmail(email: string): Promise<User | null> {
		try {
			const users = await this.dbInstance.query('Email').eq(email).exec();
			return users[0];
		} catch (error) {
			throw new Error(`Error retrieving user: ${error.message}`);
		}
	}

	async update(id: string, updateUserDto: UpdateUserDto): Promise<User | null> {
		try {
			return await this.dbInstance.update({
				Id: id,
				FirstName: updateUserDto.firstName,
				LastName: updateUserDto.lastName,
				Email: updateUserDto.email,
				ServiceProviderId: updateUserDto.serviceProviderId,
				PasswordHash: updateUserDto.passwordHash,
				MfaEnabled: updateUserDto.mfaEnabled,
				MfaType: updateUserDto.mfaType,
				RoleId: updateUserDto.roleId,
				TermsConditions: updateUserDto.termsConditions,
				PrivacyPolicy: updateUserDto.privacyPolicy,
			});
		} catch (error) {
			throw new Error(`Error updating user: ${error.message}`);
		}
	}

	async remove(id: string): Promise<void> {
		const user = await this.findOne(id);
		if (!user) {
			throw new Error('User not found in database');
		}
		await this.dbInstance.update({
			Id: id,
			Active: false,
		});
	}

	mapUserToCreateUserResponse(user: User): CreateUserResponse {
		return {
			id: user.Id,
			firstName: user.FirstName,
			lastName: user.LastName,
			email: user.Email,
			phone: user.Phone,
			type: user.type,
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

	async signin(signinDto: SignInDto) {
		const foundUser = await this.findOneByEmail(signinDto?.email);
		await this.dbOtpInstance.delete({
			email: signinDto?.email,
		});

		const authResult = await this.cognitoService.authenticateUser(
			signinDto.email,
			signinDto.password
		);
		const token = authResult.AuthenticationResult?.AccessToken;

		if (!token) {
			throw new Error('Invalid credentials');
		}

		const result = await this.generateOtp({ email: signinDto.email });

		const sqsMessage = {
			event: 'OTP_SENT',
			email: foundUser.Email,
			username:
				foundUser.FirstName +
				(foundUser.LastName ? ' ' + foundUser.LastName.charAt(0) + '.' : ''),
			otp: result.otp,
		};
		await this.sqsService.sendMessage(process.env.SQS_QUEUE_URL, sqsMessage);
		return result;
	}

	async changeUserPassword(
		authChangePasswordUserDto: AuthChangePasswordUserDto
	): Promise<string> {
		const { email, currentPassword, newPassword } = authChangePasswordUserDto;

		const userData = {
			Username: email,
			Pool: this.userPool,
		};

		const authenticationDetails = new AuthenticationDetails({
			Username: email,
			Password: currentPassword,
		});

		const userCognito = new CognitoUser(userData);

		return new Promise((resolve, reject) => {
			userCognito.authenticateUser(authenticationDetails, {
				onSuccess: function () {
					userCognito.changePassword(
						currentPassword,
						newPassword,
						async err => {
							if (err) {
								reject(`Error changing password: ${err.message}`);
							} else {
								const user = await this.findOneByEmail(
									authChangePasswordUserDto?.email
								);

								await this.dbInstance.update({
									Id: user?.Id,
									First: false,
								});
								resolve('Password changed successfully');
							}
						}
					);
				},
				onFailure: function (err) {
					reject(`Authentication failed: ${err.message}`);
				},
				newPasswordRequired: function (userAttributes) {
					delete userAttributes.email_verified;
					resolve('New password required');
				},
			});
		});
	}

	async forgotUserPassword(
		authForgotPasswordUserDto: AuthForgotPasswordUserDto
	): Promise<string> {
		const { email } = authForgotPasswordUserDto;

		const userData = {
			Username: email,
			Pool: this.userPool,
		};

		const userCognito = new CognitoUser(userData);

		return new Promise((resolve, reject) => {
			userCognito.forgotPassword({
				onSuccess: () => {
					resolve('Password reset initiated');
				},
				onFailure: err => {
					reject(`Failed to initiate password reset: ${err.message}`);
				},
			});
		});
	}

	async confirmUserPassword(
		authConfirmPasswordUserDto: AuthConfirmPasswordUserDto
	): Promise<string> {
		const { email, confirmationCode, newPassword } = authConfirmPasswordUserDto;

		const userData = {
			Username: email,
			Pool: this.userPool,
		};

		const userCognito = new CognitoUser(userData);

		return new Promise((resolve, reject) => {
			userCognito.confirmPassword(confirmationCode, newPassword, {
				onSuccess: () => {
					resolve('Password reset confirmed');
				},
				onFailure: err => {
					reject(`Failed to confirm password reset: ${err.message}`);
				},
			});
		});
	}

	async getUsersByType(getUsersDto: GetUsersDto): Promise<getUsersResponse> {
		let query = this.dbInstance.query('type');

		if (getUsersDto?.type) {
			query = query.eq(getUsersDto.type);
		} else {
			query = query.eq('WALLET');
		}

		if (getUsersDto?.firstName) {
			query = query.and().filter('FirstName').eq(getUsersDto.firstName);
		}

		if (getUsersDto?.lastName) {
			query = query.and().filter('LastName').eq(getUsersDto.lastName);
		}

		if (getUsersDto?.email) {
			query = query.and().filter('Email').eq(getUsersDto.email);
		}

		if (getUsersDto?.id) {
			query = query.and().filter('Id').eq(getUsersDto.id);
		}

		query.attributes([
			'Id',
			'type',
			'Email',
			'FirstName',
			'LastName',
			'Active',
			'State',
			'MfaEnabled',
			'MfaType',
		]);

		const users = await query.exec();

		return {
			users,
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
				email: verifyOtp?.email,
				otp: verifyOtp?.otp,
			});

			const userFind = await this.dbInstance
				.query('Email')
				.eq(verifyOtp?.email)
				.exec();

			if (userFind?.length === 0) {
				throw new Error('User not found.');
			}

			const userId = userFind?.[0].Id;

			await this.dbInstance.update({
				Id: userId,
				State: 3,
				Active: true,
			});

			const user = await this.findOneByEmail(verifyOtp.email);

			delete user.PasswordHash;
			delete user.OtpTimestamp;

			return {
				user,
				verified: true,
			};
		} catch (error) {
			console.error(error.message);
			throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}
}
