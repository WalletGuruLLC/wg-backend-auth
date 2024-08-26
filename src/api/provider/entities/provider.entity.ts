import * as dynamoose from 'dynamoose';
import { Document } from 'dynamoose/dist/Document';

const ProviderSchema = new dynamoose.Schema(
	{
		Id: {
			type: String,
			hashKey: true,
		},
		Name: String,
		Description: String,
		Email: String,
		Phone: String,
	},
	{
		timestamps: true,
	}
);

export const ProviderModel = dynamoose.model('Providers', ProviderSchema);

export interface ProviderDocument extends Document {
	Id: string;
	Name: string;
	Description: string;
	Email: string;
	Phone: string;
}
