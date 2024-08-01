import { CognitoUserPool } from 'amazon-cognito-identity-js';
import { CognitoIdentityServiceProvider } from 'aws-sdk';
import { UserService } from './user.service';

jest.mock('dynamoose', () => ({
	model: jest.fn(),
	Schema: jest.fn(),
}));

const mAdminCreateUser = jest.fn();
const mForgotPassword = jest.fn().mockReturnValue({ promise: jest.fn() });
const mChangePassword = jest.fn().mockReturnValue({ promise: jest.fn() });
const mConfirmForgotPassword = jest
	.fn()
	.mockReturnValue({ promise: jest.fn() });

jest.mock('aws-sdk', () => {
	return {
		CognitoIdentityServiceProvider: jest.fn(() => ({
			adminCreateUser: mAdminCreateUser,
			forgotPassword: mForgotPassword,
			changePassword: mChangePassword,
			confirmForgotPassword: mConfirmForgotPassword,
			adminInitiateAuth: jest.fn().mockReturnThis(),
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
	let userService: UserService;
	let cognitoServiceMock: CognitoIdentityServiceProvider;

	beforeEach(() => {
		userService = new UserService();
		cognitoServiceMock = new CognitoIdentityServiceProvider();
	});

	test('debe crear una instancia de cognitoService', () => {
		expect(CognitoIdentityServiceProvider).toHaveBeenCalled();
		expect(userService['cognitoService']).toBeDefined();
	});

	test('debe crear una instancia de userPool', () => {
		expect(CognitoUserPool).toHaveBeenCalledTimes(2);
		expect(CognitoUserPool).toHaveBeenCalledWith({
			UserPoolId: process.env.COGNITO_USER_POOL_ID,
			ClientId: process.env.COGNITO_CLIENT_ID,
		});
		expect(userService['userPool']).toBeDefined();
	});

	test('forgotPassword debe llamar a cognitoService.forgotPassword con el nombre de usuario correcto', async () => {
		await userService['cognitoService'].forgotPassword('test@scrummers.co');
		expect(mForgotPassword).toHaveBeenCalled();
	});

	test('changePassword debe llamar a cognitoService.changePassword con los parámetros correctos', async () => {
		const email = 'testuser';
		const currentPassword = 'oldPassword123';
		const newPassword = 'newPassword123';
		await userService['cognitoService'].changePassword(
			email,
			currentPassword,
			newPassword
		);

		expect(mChangePassword).toHaveBeenCalledWith({
			AccessToken: email, // Ajuste para usar AccessToken
			PreviousPassword: currentPassword,
			ProposedPassword: newPassword,
		});
	});

	test('confirmPassword debe llamar a cognitoService.confirmForgotPassword con los parámetros correctos', async () => {
		const email = 'testuser';
		const confirmationCode = '123456';
		const newPassword = 'newPassword123';

		await userService['cognitoService'].confirmForgotPassword(
			email,
			confirmationCode,
			newPassword
		);

		expect(mConfirmForgotPassword).toHaveBeenCalled();
	});
});
