import { Document } from 'dynamoose/dist/Document';

export class Module extends Document {
	Id: string;
	Belongs: string;
	Description: string;
	CreateDate?: string;
	UpdateDate?: string;
}
