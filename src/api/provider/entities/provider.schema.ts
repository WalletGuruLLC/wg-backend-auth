import * as dynamoose from 'dynamoose';
import { v4 as uuidv4 } from 'uuid';

export const ProviderSchema = new dynamoose.Schema(
	{
		Id: {
			type: String,
			hashKey: true,
			default: () => uuidv4(),
		},
		Name: String,
		Description: String,
		Email: String,
		Phone: String,
	},
	{
		timestamps: {
			createdAt: 'CreateDate',
			updatedAt: 'UpdateDate',
		},
	}
);
