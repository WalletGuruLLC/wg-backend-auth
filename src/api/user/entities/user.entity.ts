import { Document } from 'dynamoose/dist/Document';
import {
	MfaTypeUser,
	RoleUser,
	StateUser,
	TypeUser,
} from 'src/api/user/dto/user.enums';

export class User extends Document {
	Id: string = '0';
	Username: string = '';
	Email: string = '';
	Phone: string = '';
	PasswordHash: string = '';
	MfaEnabled: boolean = false;
	MfaType: string = MfaTypeUser.TOTP;
	type: TypeUser = TypeUser.PLATFORM;
	RoleId: RoleUser = RoleUser.USER;
	Active: boolean;
	State: StateUser = StateUser.VERIFY;
	Picture: string = '';
	SendSms: boolean = false;
	SendEmails: boolean = true;
	ServiceProviderId: number = 0;
	LastLogin?: Date = null;
	OtpTimestamp: Date = new Date();
}
