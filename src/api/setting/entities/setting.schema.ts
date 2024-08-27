import * as dynamoose from 'dynamoose';

export const SettingSchema = new dynamoose.Schema(
	{
		Id: {
			type: String,
			required: true,
			validate: v => (v as string).length === 6,
		},
		Belongs: {
			type: String,
			index: {
				name: 'BelongIndex',
				global: true,
			},
		},
		Key: {
			type: String,
		},
		Value: {
			type: String,
		},
	},
	{
		timestamps: {
			createdAt: 'CreateDate',
			updatedAt: 'UpdateDate',
		},
	}
);
