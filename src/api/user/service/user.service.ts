//import { sendEmail } from './../../../utils/helpers/sendEmail';
import * as dynamoose from 'dynamoose';
import * as bcrypt from 'bcrypt';
import { Injectable } from '@nestjs/common';
import { Model } from 'dynamoose/dist/Model';
import { CreateUserDto } from '../dto/create-user.dto';
import { UpdateUserDto } from '../dto/update-user.dto';
import { User } from '../entities/user.entity';
import { UserSchema } from '../entities/user.schema';
import { CognitoService } from '../cognito/cognito.service';
import { SignInDto } from '../dto/signin.dto';
import { UpdateUserPasswordDto } from '../dto/update-password-user.dto copy';
import { AuthChangePasswordUserDto } from '../dto/auth-change-password-user.dto';
import {
	AuthenticationDetails,
	CognitoUser,
	CognitoUserPool,
} from 'amazon-cognito-identity-js';
import { AuthForgotPasswordUserDto } from '../dto/auth-forgot-password-user.dto';
import { AuthConfirmPasswordUserDto } from '../dto/auth-confirm-password-user.dto';
import { cognitoConfig } from '../cognito/cognito.config';

@Injectable()
export class UserService {
	private dbInstance: Model<User>;
	private cognitoService: CognitoService;
	private userPool: CognitoUserPool;

	constructor() {
		const tableName = 'users';
		this.dbInstance = dynamoose.model<User>(tableName, UserSchema);
		this.cognitoService = new CognitoService();
		this.userPool = new CognitoUserPool(cognitoConfig);
	}

	async create(createUserDto: CreateUserDto) {
		const saltRounds = 8;
		const hashedPassword = await bcrypt.hash(
			createUserDto.PasswordHash,
			saltRounds
		);

		// Create user in Cognito
		await this.cognitoService.createUser(
			createUserDto.Email,
			createUserDto.PasswordHash,
			createUserDto.Email
		);
		// Create user in DynamoDB
		const newUser = await this.dbInstance.create({
			Id: createUserDto.Id,
			Username: createUserDto.Username,
			Email: createUserDto.Email,
			PasswordHash: hashedPassword,
			MfaEnabled: createUserDto.MfaEnabled,
			MfaType: createUserDto.MfaType,
			Rol: createUserDto.Rol,
		});

		return newUser;
	}

	async findOne(id: string) {
		return await this.dbInstance.get({ Id: id });
	}

	async findOneByEmail(email: string) {
		try {
			const users = await this.dbInstance.query('Email').eq(email).exec();
			return users[0];
		} catch (error) {
			if (
				error.message.includes(
					'The provided key element does not match the schema'
				)
			) {
				console.log('Key schema mismatch:', error);
			} else {
				console.log('Error getting user:', error);
			}
		}
	}

	async findOneByEmailAndUpdate(
		email: string,
		updateUserDto: UpdateUserPasswordDto
	) {
		const users = await this.dbInstance.query('Email').eq(email).exec();

		await this.dbInstance.update({
			Id: users?.[0]?.Id,
			Otp: updateUserDto?.Otp,
			OtpTimestamp: updateUserDto?.OtpTimestamp,
		});

		return users?.[0];
	}

	async update(id: string, updateUserDto: UpdateUserDto) {
		return await this.dbInstance.update({
			Id: id,
			Username: updateUserDto.Username,
			Email: updateUserDto.Email,
			PasswordHash: updateUserDto.PasswordHash,
			MfaEnabled: updateUserDto.MfaEnabled,
			MfaType: updateUserDto.MfaType,
			Rol: updateUserDto.Rol,
		});
	}

	async remove(id: string): Promise<void> {
		try {
			const user = await this.findOne(id);
			if (!user) {
				throw new Error('User not found in database');
			}

			try {
				await this.cognitoService.deleteUser(user.Email);
			} catch (error) {
				throw new Error(`Error deleting user from Cognito: ${error.message}`);
			}

			try {
				await this.dbInstance.delete({ Id: id });
			} catch (error) {
				throw new Error(`Error deleting user from database: ${error.message}`);
			}
		} catch (error) {
			throw new Error(`Failed to remove user: ${error.message}`);
		}
	}

	async signin(signinDto: SignInDto) {
		const user = await this.findOneByEmail(signinDto.email);
		if (!user) {
			return 'User not found';
		}

		try {
			const authResult = await this.cognitoService.authenticateUser(
				signinDto.email,
				signinDto.password
			);
			const token = authResult.AuthenticationResult?.AccessToken;

			if (!token) {
				return 'Invalid credentials';
			}

			return { token, user };
		} catch (error) {
			throw new Error(`Authentication failed: ${error.message}`);
		}
	}

	async changeUserPassword(
		authChangePasswordUserDto: AuthChangePasswordUserDto
	) {
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
				onSuccess: () => {
					userCognito.changePassword(
						currentPassword,
						newPassword,
						(err, result) => {
							if (err) {
								reject(err);
								return;
							}
							resolve(result);
						}
					);
				},
				onFailure: err => {
					reject(err);
				},
			});
		});
	}

	async forgotUserPassword(
		authForgotPasswordUserDto: AuthForgotPasswordUserDto
	) {
		const { email } = authForgotPasswordUserDto;

		const userData = {
			Username: email,
			Pool: this.userPool,
		};

		const userCognito = new CognitoUser(userData);

		return new Promise((resolve, reject) => {
			userCognito.forgotPassword({
				onSuccess: result => {
					resolve(result);
				},
				onFailure: err => {
					reject(err);
				},
			});
		});
	}

	async confirmUserPassword(
		authConfirmPasswordUserDto: AuthConfirmPasswordUserDto
	) {
		const { email, confirmationCode, newPassword } = authConfirmPasswordUserDto;

		const userData = {
			Username: email,
			Pool: this.userPool,
		};

		const userCognito = new CognitoUser(userData);

		return new Promise((resolve, reject) => {
			userCognito.confirmPassword(confirmationCode, newPassword, {
				onSuccess: () => {
					resolve({ status: 'success' });
				},
				onFailure: err => {
					reject(err);
				},
			});
		});
	}
}
