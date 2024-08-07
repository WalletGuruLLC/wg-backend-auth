import { Injectable } from '@nestjs/common';
import {
	AuthenticationDetails,
	CognitoUser,
	CognitoUserPool,
} from 'amazon-cognito-identity-js';
import * as bcrypt from 'bcrypt';
import * as dynamoose from 'dynamoose';
import { Model } from 'dynamoose/dist/Model';
import { CognitoService } from '../cognito/cognito.service';
import { AuthChangePasswordUserDto } from '../dto/auth-change-password-user.dto';
import { AuthConfirmPasswordUserDto } from '../dto/auth-confirm-password-user.dto';
import { AuthForgotPasswordUserDto } from '../dto/auth-forgot-password-user.dto';
import { CreateUserDto } from '../dto/create-user.dto';
import { CreateUserResponse, SignInResponse } from '../dto/responses';
import { SignInDto } from '../dto/signin.dto';
import { UpdateUserDto } from '../dto/update-user.dto';
import { User } from '../entities/user.entity';
import { UserSchema } from '../entities/user.schema';

@Injectable()
export class UserService {
	private dbInstance: Model<User>;
	private cognitoService: CognitoService;
	private userPool: CognitoUserPool;

	constructor() {
		const tableName = 'users';
		this.dbInstance = dynamoose.model<User>(tableName, UserSchema);
		this.cognitoService = new CognitoService();
		this.userPool = new CognitoUserPool({
			UserPoolId: process.env.COGNITO_USER_POOL_ID,
			ClientId: process.env.COGNITO_CLIENT_ID,
		});
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
			Username: createUserDto.username,
			Email: createUserDto.email,
			PasswordHash: hashedPassword,
			MfaEnabled: createUserDto.mfaEnabled,
			ServiceProviderId: createUserDto.serviceProviderId,
			MfaType: createUserDto.mfaType,
			RoleId: createUserDto.roleId,
			type: createUserDto.type,
			Active: createUserDto.active,
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
				Username: updateUserDto.username,
				Email: updateUserDto.email,
				ServiceProviderId: updateUserDto.serviceProviderId,
				PasswordHash: updateUserDto.passwordHash,
				MfaEnabled: updateUserDto.mfaEnabled,
				MfaType: updateUserDto.mfaType,
				RoleId: updateUserDto.roleId,
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

		await this.cognitoService.deleteUser(user.Email);
		await this.dbInstance.delete({ Id: id });
	}

	mapUserToCreateUserResponse(user: User): CreateUserResponse {
		return {
			id: user.Id,
			userName: user.Username,
			email: user.Email,
			phone: user.Phone,
			type: user.type,
			roleId: user.RoleId,
			active: user.PasswordHash !== '',
			state: user.State,
			serviceProviderId: user.ServiceProviderId,
			lastLogin: user.LastLogin,
		};
	}

	async signin(signinDto: SignInDto): Promise<SignInResponse> {
		const user = await this.findOneByEmail(signinDto.email);
		if (!user) {
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

		const lastLogin = new Date();
		user.LastLogin = lastLogin;

		await user.save();

		return {
			token,
			user: this.mapUserToCreateUserResponse(user),
		};
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
}
