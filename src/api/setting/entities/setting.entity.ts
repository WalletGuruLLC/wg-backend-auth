import { Document } from 'dynamoose/dist/Document';

export class Setting extends Document {
	Id: string;
	Belongs: string;
	Key: string;
	Value: string;
	CreateDate?: string;
	UpdateDate?: string;
}
