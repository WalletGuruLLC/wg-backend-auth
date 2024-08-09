import { RoleUser, StateUser, TypeUser } from './user.enums';

export interface ApiResponse<T> {
	statusCode: number;
	message: string;
	data?: T;
}

export interface CreateUserResponse {
	id: string;
	userName: string;
	email: string;
	phone: string;
	type: TypeUser;
	roleId: RoleUser;
	active: boolean;
	state: StateUser;
	serviceProviderId: number;
	lastLogin: Date | null;
	first: boolean;
	accessLevel?: string;
}

export interface SignInResponse {
	token: string;
	user: CreateUserResponse;
}

export interface getUsersResponse {
	users: Array<any>;
}
