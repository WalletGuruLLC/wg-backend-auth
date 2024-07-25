// src/api/user/cognito/cognito.service.ts

import { CognitoIdentityServiceProvider } from 'aws-sdk';
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
			Username: username,
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
}
