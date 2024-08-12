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

@Injectable()
export class UserService {
	private dbInstance: Model<User>;
	private dbOtpInstance: Model<Otp>;
	private cognitoService: CognitoService;
	private userPool: CognitoUserPool;

	constructor() {
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

	async verifyOtp(verifyOtp: VerifyOtpDto): Promise<any> {
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

	async create(createUserDto: CreateUserDto): Promise<CreateUserResponse> {
		const saltRounds = 8;
		const hashedPassword = await bcrypt.hash(
			createUserDto.passwordHash,
			saltRounds
		);

		// Create user in Cognito
		await this.cognitoService.createUser(
			createUserDto.email,
			createUserDto.passwordHash,
			createUserDto.email
		);

		// Create user in DynamoDB
		const newUser = await this.dbInstance.create({
			Id: createUserDto.id,
			FirstName: createUserDto.firstName,
			LastName: createUserDto.lastName,
			Email: createUserDto.email,
			PasswordHash: hashedPassword,
			MfaEnabled: createUserDto.mfaEnabled,
			ServiceProviderId: createUserDto.serviceProviderId,
			MfaType: createUserDto.mfaType,
			RoleId: createUserDto.roleId,
			type: createUserDto.type,
			Active: createUserDto.active,
			TermsConditions: createUserDto.termsConditions,
			PrivacyPolicy: createUserDto.privacyPolicy,
		});

		return this.mapUserToCreateUserResponse(newUser);
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
		const userFind = await this.findOneByEmailValidationAttributes(
			signinDto.email
		);
		if (!userFind) {
			throw new Error('User not found');
		}

		const authResult = await this.cognitoService.authenticateUser(
			signinDto.email,
			signinDto.password
		);
		const token = authResult.AuthenticationResult?.AccessToken;

		if (!token) {
			throw new Error('Invalid credentials');
		}

		const result = await this.generateOtp({ email: signinDto.email });
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
				onSuccess: function (result) {
					userCognito.changePassword(
						currentPassword,
						newPassword,
						async (err, result) => {
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
				newPasswordRequired: function (userAttributes, requiredAttributes) {
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
				onSuccess: result => {
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
		const users = await this.dbInstance
			.query('type')
			.eq(getUsersDto?.type || 'PLATFORM')
			.attributes(['Id', 'type', 'Email', 'Username', 'MfaEnabled', 'MfaType'])
			.exec();

		return {
			users,
		};
	}
}
