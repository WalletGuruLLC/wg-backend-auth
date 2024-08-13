import * as dynamoose from 'dynamoose';

export const ModuleSchema = new dynamoose.Schema(
	{
		Id: {
			type: String,
			required: true,
			validate: v => (v as string).length === 4,
		},
		Description: {
			type: String,
			required: true,
			validate: v => (v as string).length <= 30,
		},
	},
	{
		timestamps: {
			createdAt: 'CreateDate',
			updatedAt: 'UpdateDate',
		},
	}
);
