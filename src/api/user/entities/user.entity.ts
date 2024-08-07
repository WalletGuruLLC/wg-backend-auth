import { Document } from 'dynamoose/dist/Document';
import {
	MfaTypeUser,
	RoleUser,
	StateUser,
	TypeUser,
} from 'src/api/user/dto/user.enums';

export class User extends Document {
	Id = '0';
	Username = '';
	Email = '';
	Phone = '';
	PasswordHash = '';
	MfaEnabled = false;
	MfaType: string = MfaTypeUser.TOTP;
	type: TypeUser = TypeUser.PLATFORM;
	RoleId: RoleUser = RoleUser.USER;
	Active: boolean;
	First: boolean;
	State: StateUser = StateUser.VERIFY;
	Picture = '';
	SendSms = false;
	SendEmails = true;
	ServiceProviderId = 0;
	LastLogin?: Date = null;
	OtpTimestamp: Date = new Date();
}
