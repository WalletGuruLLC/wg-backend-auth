import { Document } from 'dynamoose/dist/Document';
export class Role extends Document {
	Id: string;
	Name: string;
	Description: string;
	Active: boolean;
	Modules: object;
}
