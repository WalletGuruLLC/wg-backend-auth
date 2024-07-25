// src/api/user/cognito/cognito.interface.ts

export interface CognitoServiceInterface {
	createUser(username: string, password: string, email: string): Promise<any>;
}
