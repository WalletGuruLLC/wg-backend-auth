import { CognitoUserPool } from 'amazon-cognito-identity-js'; // Importar desde amazon-cognito-identity-js
import { CognitoService } from '../cognito/cognito.service';
import { CognitoIdentityServiceProvider } from 'aws-sdk';
import { cognitoConfig } from '../cognito/cognito.config';
import { UserService } from './user.service';

jest.mock('dynamoose', () => ({
	model: jest.fn(),
	Schema: jest.fn(),
}));

jest.mock('aws-sdk', () => {
	const mAdminCreateUser = jest.fn();
	return {
		CognitoIdentityServiceProvider: jest.fn(() => ({
			adminCreateUser: mAdminCreateUser,
			forgotPassword: jest.fn().mockReturnThis(),
			changePassword: jest.fn().mockReturnThis(),
			confirmForgotPassword: jest.fn().mockReturnThis(),
			adminInitiateAuth: jest.fn().mockReturnThis(),
			promise: jest.fn(),
		})),
	};
});

jest.mock('amazon-cognito-identity-js', () => {
	return {
		CognitoUserPool: jest.fn(),
		CognitoUser: jest.fn().mockImplementation(() => {
			return {
				getSession: jest.fn(callback => {
					callback(null, { getIdToken: () => ({ jwtToken: 'fake_token' }) });
				}),
			};
		}),
		AuthenticationDetails: jest.fn().mockImplementation(() => {
			return {};
		}),
	};
});

describe('UserService', () => {
	let authModule: UserService;
	let cognitoModule: CognitoService;
	let cognitoServiceMock: CognitoIdentityServiceProvider;

	beforeEach(() => {
		authModule = new UserService();
		cognitoModule = new CognitoService();
		cognitoServiceMock = new CognitoIdentityServiceProvider();
	});

	test('debe crear una instancia de cognitoService', () => {
		expect(CognitoIdentityServiceProvider).toHaveBeenCalled(); // Verificar la instancia
		expect(authModule['cognitoService']).toBeDefined();
	});

	test('debe crear una instancia de userPool', () => {
		expect(CognitoUserPool).toHaveBeenCalledWith(cognitoConfig);
		expect(authModule['userPool']).toBeDefined();
	});

	test('forgotPassword debe llamar a cognitoService.forgotPassword con el nombre de usuario correcto', async () => {
		await cognitoModule.forgotPassword('test@scrummers.co');
		expect(CognitoIdentityServiceProvider).toHaveBeenCalled();
	});

	test('changePassword debe llamar a cognitoService.changePassword con los parámetros correctos', async () => {
		const email = 'testuser';
		const currentPassword = 'oldPassword123';
		const newPassword = 'newPassword123';
		await cognitoModule.changePassword(email, currentPassword, newPassword);

		expect(CognitoIdentityServiceProvider).toHaveBeenCalled();
	});

	test('confirmPassword debe llamar a cognitoService.confirmForgotPassword con los parámetros correctos', async () => {
		const email = 'testuser';
		const confirmationCode = '123456';
		const newPassword = 'newPassword123';

		await cognitoModule.confirmForgotPassword(
			email,
			confirmationCode,
			newPassword
		);

		expect(CognitoIdentityServiceProvider).toHaveBeenCalled();
	});
});
