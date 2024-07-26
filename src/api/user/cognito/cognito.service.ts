import { CognitoIdentityServiceProvider, AWSError } from 'aws-sdk';
import { cognitoConfig } from './cognito.config';
import { CognitoServiceInterface } from './cognito.interface';

export class CognitoService implements CognitoServiceInterface {
	private cognitoISP: CognitoIdentityServiceProvider;

	constructor() {
		this.cognitoISP = new CognitoIdentityServiceProvider({
			region: cognitoConfig.Region,
		});
	}

	async createUser(
		username: string,
		password: string,
		email: string
	): Promise<any> {
		const params = {
			UserPoolId: cognitoConfig.UserPoolId,
			Username: email, // Assumes email is used as username
			TemporaryPassword: password,
			UserAttributes: [
				{ Name: 'email', Value: email },
				{ Name: 'email_verified', Value: 'true' },
			],
		};

		try {
			return await this.cognitoISP.adminCreateUser(params).promise();
		} catch (error) {
			throw new Error(`Error creating user in Cognito: ${error.message}`);
		}
	}

	async deleteUser(username: string): Promise<void> {
		const params = {
			UserPoolId: cognitoConfig.UserPoolId,
			Username: username,
		};

		try {
			await this.cognitoISP.adminDeleteUser(params).promise();
		} catch (error) {
			throw new Error(`Error deleting user in Cognito: ${error.message}`);
		}
	}

	async authenticateUser(username: string, password: string): Promise<any> {
		const params = {
			AuthFlow: 'ADMIN_NO_SRP_AUTH',
			UserPoolId: cognitoConfig.UserPoolId,
			ClientId: cognitoConfig.ClientId,
			AuthParameters: {
				USERNAME: username,
				PASSWORD: password,
			},
		};

		try {
			return await this.cognitoISP.adminInitiateAuth(params).promise();
		} catch (error) {
			throw new Error(`Error authenticating user in Cognito: ${error.message}`);
		}
	}

	async changePassword(
		accessToken: string,
		previousPassword: string,
		proposedPassword: string
	): Promise<void> {
		const params = {
			AccessToken: accessToken,
			PreviousPassword: previousPassword,
			ProposedPassword: proposedPassword,
		};

		try {
			await this.cognitoISP.changePassword(params).promise();
		} catch (error) {
			throw new Error(`Error changing password in Cognito: ${error.message}`);
		}
	}

	async forgotPassword(username: string): Promise<void> {
		const params = {
			ClientId: cognitoConfig.ClientId,
			Username: username,
		};

		try {
			await this.cognitoISP.forgotPassword(params).promise();
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
	): Promise<void> {
		const params = {
			ClientId: cognitoConfig.ClientId,
			Username: username,
			ConfirmationCode: confirmationCode,
			Password: newPassword,
		};

		try {
			await this.cognitoISP.confirmForgotPassword(params).promise();
		} catch (error) {
			throw new Error(
				`Error confirming new password in Cognito: ${error.message}`
			);
		}
	}
}
