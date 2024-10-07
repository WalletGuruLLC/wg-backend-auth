import * as dynamoose from 'dynamoose';
import { v4 as uuidv4 } from 'uuid';

export const NotificationSettingsSchema = new dynamoose.Schema(
	{
		Id: {
			type: String,
			hashKey: true,
			default: () => uuidv4(),
		},
		UserId: {
			type: String,
		},
		NotificationsActive: {
			type: Boolean,
			default: true,
		},
		MuteUntil: {
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
