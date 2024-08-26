import * as dynamoose from 'dynamoose';
import { v4 as uuidv4 } from 'uuid';

export const AuthAttemptSchema = new dynamoose.Schema(
	{
		id: {
			type: String,
			default: () => uuidv4(),
		},
		email: {
			type: String,
			required: true,
		},
		section: {
			type: String,
			required: true,
		},
		status: {
			type: String,
			enum: ['success', 'failure'],
			required: true,
		},
	},
	{
		timestamps: {
			createdAt: 'CreateDate',
			updatedAt: 'UpdateDate',
		},
	}
);

export const AuthAttemptModel = dynamoose.model('Attempts', AuthAttemptSchema);
