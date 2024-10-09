import { Document } from 'dynamoose/dist/Document';

export class NotificationSettings extends Document {
	Id: string;
	UserId: string;
	NotificationsActive: boolean;
	MuteUntil: number;
	CreateDate: Date;
	UpdateDate: Date;
}
