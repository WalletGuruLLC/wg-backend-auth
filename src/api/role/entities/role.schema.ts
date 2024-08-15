import * as dynamoose from 'dynamoose';

export const RoleSchema = new dynamoose.Schema(
	{
		Id: {
			type: String,
			hashKey: true,
		},
		Name: String,
		Description: String,
		Active: {
			type: Boolean,
			default: true,
		},
	},
	{
		timestamps: {
			createdAt: 'CreateDate',
			updatedAt: 'UpdateDate',
		},
	}
);
