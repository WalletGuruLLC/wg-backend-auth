import { CognitoIdentityServiceProvider } from 'aws-sdk';
import { createHmac } from 'crypto';
import { CognitoServiceInterface } from './cognito.interface';
import {
	AuthenticateUserResponse,
	AuthenticationResult,
	ChangePasswordResponse,
	ConfirmForgotPasswordResponse,
	CreateUserResponse,
	ForgotPasswordResponse,
} from './cognito.types';
import * as Sentry from '@sentry/nestjs';
import { HttpException } from '@nestjs/common';
import { HttpStatus } from '../../../utils/constants';

export class CognitoService implements CognitoServiceInterface {
	private cognitoISP: CognitoIdentityServiceProvider;

	constructor() {
		this.cognitoISP = new CognitoIdentityServiceProvider({
			region: process.env.AWS_REGION,
		});
	}

	async createUser(
		username: string,
		password: string,
		email: string
	): Promise<CreateUserResponse> {
		const params = {
			UserPoolId: process.env.COGNITO_USER_POOL_ID,
			Username: email,
			TemporaryPassword: password,
			UserAttributes: [
				{ Name: 'email', Value: email },
				{ Name: 'email_verified', Value: 'true' },
			],
			MessageAction: 'SUPPRESS',
		};

		try {
			const user = await this.cognitoISP.adminCreateUser(params).promise();

			const paramsAdminSetUserPassword = {
				UserPoolId: process.env.COGNITO_USER_POOL_ID,
				Username: email,
				Password: password,
				Permanent: true,
			};
			await this.cognitoISP
				.adminSetUserPassword(paramsAdminSetUserPassword)
				.promise();

			return user as CreateUserResponse;
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error creating user in Cognito: ${error.message}`);
		}
	}

	async deleteUser(username: string): Promise<void> {
		const params = {
			UserPoolId: process.env.COGNITO_USER_POOL_ID,
			Username: username,
		};

		try {
			await this.cognitoISP.adminDeleteUser(params).promise();
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error deleting user in Cognito: ${error.message}`);
		}
	}

	async authenticateUser(
		username: string,
		password: string
	): Promise<AuthenticateUserResponse> {
		const hasher = createHmac('sha256', process.env.COGNITO_CLIENT_SECRET_ID);
		hasher.update(`${username}${process.env.COGNITO_CLIENT_ID}`);
		const secretHash = hasher.digest('base64');

		const params = {
			AuthFlow: 'ADMIN_NO_SRP_AUTH',
			UserPoolId: process.env.COGNITO_USER_POOL_ID,
			ClientId: process.env.COGNITO_CLIENT_ID,
			AuthParameters: {
				USERNAME: username,
				PASSWORD: password,
				SECRET_HASH: secretHash,
			},
		};

		try {
			return (await this.cognitoISP
				.adminInitiateAuth(params)
				.promise()) as AuthenticateUserResponse;
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error authenticating user in Cognito: ${error.message}`);
		}
	}

	async refreshToken(token: string, username: string): Promise<string> {
		const hasher = createHmac('sha256', process.env.COGNITO_CLIENT_SECRET_ID);
		hasher.update(`${username}${process.env.COGNITO_CLIENT_ID}`);
		const secretHash = hasher.digest('base64');
		const params = {
			AuthFlow: 'REFRESH_TOKEN_AUTH',
			ClientId: process.env.COGNITO_CLIENT_ID,
			AuthParameters: {
				REFRESH_TOKEN: token,
				SECRET_HASH: secretHash,
			},
		};

		try {
			const response = await this.cognitoISP.initiateAuth(params).promise();

			return response?.AuthenticationResult?.AccessToken;
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	async changePassword(
		accessToken: string,
		previousPassword: string,
		proposedPassword: string
	): Promise<ChangePasswordResponse> {
		const params = {
			AccessToken: accessToken,
			PreviousPassword: previousPassword,
			ProposedPassword: proposedPassword,
		};

		try {
			(await this.cognitoISP
				.changePassword(params)
				.promise()) as ChangePasswordResponse;
			return {};
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					statusCode: HttpStatus.UNAUTHORIZED,
					customCode: 'WGE0007',
				},
				HttpStatus.UNAUTHORIZED
			);
		}
	}

	async forgotPassword(username: string): Promise<ForgotPasswordResponse> {
		const hasher = createHmac('sha256', process.env.COGNITO_CLIENT_SECRET_ID);
		hasher.update(`${username}${process.env.COGNITO_CLIENT_ID}`);
		const secretHash = hasher.digest('base64');

		const params = {
			ClientId: process.env.COGNITO_CLIENT_ID,
			Username: username,
			SecretHash: secretHash,
		};

		try {
			(await this.cognitoISP
				.forgotPassword(params)
				.promise()) as ForgotPasswordResponse;
			return {};
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(
				`Error in forgot password process in Cognito: ${error.message}`
			);
		}
	}

	async confirmForgotPassword(
		username: string,
		confirmationCode: string,
		newPassword: string
	): Promise<any> {
		const hasher = createHmac('sha256', process.env.COGNITO_CLIENT_SECRET_ID);
		hasher.update(`${username}${process.env.COGNITO_CLIENT_ID}`);
		const secretHash = hasher.digest('base64');

		const params = {
			ClientId: process.env.COGNITO_CLIENT_ID,
			Username: username,
			ConfirmationCode: confirmationCode,
			Password: newPassword,
			SecretHash: secretHash,
		};

		try {
			(await this.cognitoISP
				.confirmForgotPassword(params)
				.promise()) as ConfirmForgotPasswordResponse;
			return {};
		} catch (error) {
			Sentry.captureException(error);
			return {
				customCode: 'WGE0005',
			};
		}
	}

	async revokeToken(token: string) {
		const params = {
			ClientId: process.env.COGNITO_CLIENT_ID,
			ClientSecret: process.env.COGNITO_CLIENT_SECRET_ID,
			Token: token,
		};

		try {
			await this.cognitoISP.revokeToken(params).promise();
			return {};
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(
				`Error revoke token process in Cognito: ${error.message}`
			);
		}
	}
}
