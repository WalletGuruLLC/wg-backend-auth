import { Document } from 'dynamoose/dist/Document';
import { MfaTypeUser, StateUser, TypeUser } from 'src/api/user/dto/user.enums';

export class User extends Document {
	Id = '';
	FirstName = '';
	LastName = '';
	Email = '';
	Phone = '';
	PasswordHash = '';
	MfaEnabled = false;
	MfaType: string = MfaTypeUser.TOTP;
	type: TypeUser = TypeUser.PLATFORM;
	RoleId = '';
	Active: boolean;
	First: boolean;
	State: StateUser = StateUser.VERIFY;
	Picture = '';
	SendSms = false;
	SendEmails = true;
	ServiceProviderId = '';
	LastLogin?: Date = null;
	OtpTimestamp: Date = new Date();
	TermsConditions = false;
	PrivacyPolicy = false;
}
