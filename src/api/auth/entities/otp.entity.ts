import { Document } from 'dynamoose/dist/Document';

export class Otp extends Document {
	email = '';
	otp = '';
	createdAt: Date = new Date();
}
