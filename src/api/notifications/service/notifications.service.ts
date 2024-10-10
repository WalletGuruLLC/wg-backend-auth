import * as dynamoose from 'dynamoose';
import { Model } from 'dynamoose/dist/Model';
import { v4 as uuidv4 } from 'uuid';
import { Injectable } from '@nestjs/common';
import { User } from '../../user/entities/user.entity';
import { UserSchema } from '../../user/entities/user.schema';
import { convertToCamelCase } from '../../../utils/helpers/convertCamelCase';
import { NotificationSettings } from '../entities/notification.entity';
import { NotificationSettingsSchema } from '../entities/notification.schema';
import * as moment from 'moment';

@Injectable()
export class NotificationsService {
	private readonly dbInstance: Model<NotificationSettings>;
	private dbUserInstance: Model<User>;

	constructor() {
		const tableName = 'NotificationSettings';
		this.dbInstance = dynamoose.model<NotificationSettings>(
			tableName,
			NotificationSettingsSchema
		);
		this.dbUserInstance = dynamoose.model<User>('Users', UserSchema);
	}
	async getUserNotificationSettings(userId: string) {
		const settings = await this.dbInstance.scan('UserId').eq(userId).exec();
		return settings?.[0];
	}

	async toggleNotifications(userId: string, isActive: boolean) {
		let settings: any = await this.dbInstance.scan('UserId').eq(userId).exec();

		if (!settings || settings.length === 0) {
			const newSetting = {
				Id: uuidv4(),
				UserId: userId,
				NotificationsActive: true,
				MuteUntil: 0,
			};
			await this.dbInstance.create(newSetting);
			settings = [newSetting];
		}

		const result = await this.dbInstance.update({
			Id: settings[0].Id,
			MuteUntil: 0,
			NotificationsActive: isActive,
		});

		return convertToCamelCase(result);
	}

	async muteNotifications(userId: string, duration: string) {
		let settings: any = await this.dbInstance.scan('UserId').eq(userId).exec();

		if (!settings || settings.length === 0) {
			const newSetting = {
				Id: uuidv4(),
				UserId: userId,
				NotificationsActive: true,
				MuteUntil: 0,
			};
			await this.dbInstance.create(newSetting);
			settings = [newSetting];
		}

		let MuteUntil: number;
		const now = moment();
		switch (duration) {
			case '30m':
				MuteUntil = now.add(30, 'minutes').unix();
				break;
			case '1h':
				MuteUntil = now.add(1, 'hour').unix();
				break;
			case 'never':
				MuteUntil = -1;
				break;
			default:
				MuteUntil = -1;
				break;
		}

		const result = await this.dbInstance.update({
			Id: settings[0].Id,
			MuteUntil: MuteUntil,
			NotificationsActive: false,
		});

		return convertToCamelCase(result);
	}

	async areNotificationsActive(userId: string) {
		const settings = await this.getUserNotificationSettings(userId);
		const now = moment().unix();
		if (
			settings.MuteUntil &&
			settings.MuteUntil !== -1 &&
			settings.MuteUntil < now
		) {
			// Si el mute ha expirado
			settings.MuteUntil = 0;
			settings.NotificationsActive = true;
			await settings.save();
		}
		return convertToCamelCase(settings.NotificationsActive);
	}
}
