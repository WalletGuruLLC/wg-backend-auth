// src/api/user/cognito/cognito.service.spec.ts

import { CognitoService } from './cognito.service';
import { CognitoIdentityServiceProvider } from 'aws-sdk';

// Mock de CognitoIdentityServiceProvider
jest.mock('aws-sdk', () => {
	const mAdminCreateUser = jest.fn();
	return {
		CognitoIdentityServiceProvider: jest.fn(() => ({
			adminCreateUser: mAdminCreateUser,
		})),
	};
});

describe('CognitoService', () => {
	let cognitoService: CognitoService;
	let cognitoISP: jest.Mocked<CognitoIdentityServiceProvider>;
	let mockPromise: jest.Mock;

	beforeEach(() => {
		cognitoService = new CognitoService();
		cognitoISP =
			new CognitoIdentityServiceProvider() as jest.Mocked<CognitoIdentityServiceProvider>;

		mockPromise = jest.fn();
		cognitoISP.adminCreateUser.mockReturnValue({
			promise: mockPromise,
		} as any);
	});

	it('debería crear un usuario en Cognito', async () => {
		// Configura el mock para devolver un valor específico
		const expectedResponse = { User: { Username: 'testuser' } };
		mockPromise.mockResolvedValue(expectedResponse);

		const result = await cognitoService.createUser(
			'testuser',
			'password123',
			'test@example.com'
		);
		expect(result).toEqual(expectedResponse);
		expect(cognitoISP.adminCreateUser).toHaveBeenCalledWith({
			UserPoolId: 'us-east-2_EhbAxcCTT',
			Username: 'testuser',
			TemporaryPassword: 'password123',
			UserAttributes: [
				{ Name: 'email', Value: 'test@example.com' },
				{ Name: 'email_verified', Value: 'true' },
			],
		});
	});

	it('debería manejar errores al crear un usuario', async () => {
		const errorMessage = 'Error creating user';
		mockPromise.mockRejectedValue(new Error(errorMessage));

		await expect(
			cognitoService.createUser('testuser', 'password123', 'test@example.com')
		).rejects.toThrow(`Error creating user in Cognito: ${errorMessage}`);
	});
});
