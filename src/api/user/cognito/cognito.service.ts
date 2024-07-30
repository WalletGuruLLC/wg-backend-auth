import { CognitoIdentityServiceProvider } from 'aws-sdk';
import { CognitoServiceInterface } from './cognito.interface';
import {
	CreateUserResponse,
	AuthenticateUserResponse,
	ChangePasswordResponse,
	ForgotPasswordResponse,
	ConfirmForgotPasswordResponse,
} from './cognito.types';

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
			Username: email, // Assumes email is used as username
			TemporaryPassword: password,
			UserAttributes: [
				{ Name: 'email', Value: email },
				{ Name: 'email_verified', Value: 'true' },
			],
		};

		try {
			return (await this.cognitoISP
				.adminCreateUser(params)
				.promise()) as CreateUserResponse;
		} catch (error) {
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
			throw new Error(`Error deleting user in Cognito: ${error.message}`);
		}
	}

	async authenticateUser(
		username: string,
		password: string
	): Promise<AuthenticateUserResponse> {
		const params = {
			AuthFlow: 'ADMIN_NO_SRP_AUTH',
			UserPoolId: process.env.COGNITO_USER_POOL_ID,
			ClientId: process.env.COGNITO_CLIENT_ID,
			AuthParameters: {
				USERNAME: username,
				PASSWORD: password,
			},
		};

		try {
			return (await this.cognitoISP
				.adminInitiateAuth(params)
				.promise()) as AuthenticateUserResponse;
		} catch (error) {
			throw new Error(`Error authenticating user in Cognito: ${error.message}`);
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
			throw new Error(`Error changing password in Cognito: ${error.message}`);
		}
	}

	async forgotPassword(username: string): Promise<ForgotPasswordResponse> {
		const params = {
			ClientId: process.env.COGNITO_CLIENT_ID,
			Username: username,
		};

		try {
			(await this.cognitoISP
				.forgotPassword(params)
				.promise()) as ForgotPasswordResponse;
			return {};
		} catch (error) {
			throw new Error(
				`Error in forgot password process in Cognito: ${error.message}`
			);
		}
	}

	async confirmForgotPassword(
		username: string,
		confirmationCode: string,
		newPassword: string
	): Promise<ConfirmForgotPasswordResponse> {
		const params = {
			ClientId: process.env.COGNITO_CLIENT_ID,
			Username: username,
			ConfirmationCode: confirmationCode,
			Password: newPassword,
		};

		try {
			(await this.cognitoISP
				.confirmForgotPassword(params)
				.promise()) as ConfirmForgotPasswordResponse;
			return {};
		} catch (error) {
			throw new Error(
				`Error confirming new password in Cognito: ${error.message}`
			);
		}
	}
}
