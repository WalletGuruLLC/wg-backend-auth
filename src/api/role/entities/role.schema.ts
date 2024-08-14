import * as dynamoose from 'dynamoose';

export const RoleSchema = new dynamoose.Schema(
	{
		Id: {
			type: String,
			hashKey: true,
		},
		Name: String,
		Description: String,
	},
	{
		timestamps: {
			createdAt: 'CreateDate',
			updatedAt: 'UpdateDate',
		},
	}
);
