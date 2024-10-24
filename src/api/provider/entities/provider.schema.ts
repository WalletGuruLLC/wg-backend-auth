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
		EINNumber: String,
		Country: String,
		City: String,
		ZipCode: String,
		CompanyAddress: String,
		WalletAddress: String,
		Logo: String,
		ContactInformation: String,
		Active: {
			type: Boolean,
			default: true,
		},
		ImageUrl: {
			type: String,
			default:
				'https://walletguru-dev.s3.us-east-2.amazonaws.com/Card+Generica+Service+Providers.png',
		},
		Asset: {
			type: String,
			default: 'USD',
		},
	},
	{
		timestamps: {
			createdAt: 'CreateDate',
			updatedAt: 'UpdateDate',
		},
	}
);
