import * as dynamoose from 'dynamoose';

export const ModuleSchema = new dynamoose.Schema(
	{
		Id: {
			type: String,
			required: true,
			validate: v => (v as string).length === 4,
		},
		Belongs: {
			type: String,
			index: {
				name: 'BelongsIndex',
				global: true,
			},
		},
		Description: {
			type: String,
			required: true,
			validate: v => (v as string).length <= 30,
		},
		Index: {
			type: Number,
			default: 0,
		},
		SubIndex: {
			type: Number,
			default: 0,
		},
	},
	{
		timestamps: {
			createdAt: 'CreateDate',
			updatedAt: 'UpdateDate',
		},
	}
);
