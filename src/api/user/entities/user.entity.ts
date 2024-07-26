import { Document } from 'dynamoose/dist/Document';

export class User extends Document {
	Id = '0';
	Username = '';
	Email = '';
	PasswordHash = '';
	MfaEnabled = false;
	MfaType = 'TOTP';
	Rol = 'user';
	Otp = '';
	OtpTimestamp = new Date();
}
