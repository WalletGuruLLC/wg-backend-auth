import {
	MfaTypeUser,
	RoleUser,
	StateUser,
	TypeUser,
} from 'src/api/user/dto/user.enums';

export class CreateUserDto {
	id: string;
	firstName: string;
	lastName: string;
	email: string;
	phone: string;
	passwordHash: string;
	mfaEnabled: boolean;
	mfaType: MfaTypeUser;
	type: TypeUser;
	roleId: RoleUser;
	active: boolean;
	state: StateUser;
	picture: string;
	sendSms: boolean;
	sendEmails: boolean;
	serviceProviderId: number;
	lastLogin: Date;
	termsConditions: boolean;
	privacyPolicy: boolean;
}
