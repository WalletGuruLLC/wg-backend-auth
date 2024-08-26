import { Document } from 'dynamoose/dist/Document';

export interface Provider extends Document {
	Id: string;
	Name: string;
	Description: string;
	Email: string;
	Phone: string;
}
