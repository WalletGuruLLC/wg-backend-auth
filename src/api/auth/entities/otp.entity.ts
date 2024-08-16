import { Document } from 'dynamoose/dist/Document';

export class Otp extends Document {
	email = '';
	otp = '';
	token = '';
	createdAt: Date = new Date();
}
