import { Document } from 'dynamoose/dist/Document';

export class Otp extends Document {
	Email = '';
	Otp = '';
	Token = '';
	RefreshToken = '';
	CreatedAt: Date = new Date();
}
