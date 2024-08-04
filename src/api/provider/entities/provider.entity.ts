import * as dynamoose from 'dynamoose';
import { Document } from 'dynamoose/dist/Document';

const ProviderSchema = new dynamoose.Schema(
	{
		id: {
			type: String,
			hashKey: true,
		},
		name: String,
		description: String,
		email: String,
		phone: String,
	},
	{
		timestamps: true,
	}
);

export const ProviderModel = dynamoose.model('Provider', ProviderSchema);

export interface ProviderDocument extends Document {
	id: string;
	name: string;
	description: string;
	email: string;
	phone: string;
}
