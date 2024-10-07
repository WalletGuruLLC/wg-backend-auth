import * as dynamoose from 'dynamoose';
import { Model } from 'dynamoose/dist/Model';
import { Injectable, BadRequestException } from '@nestjs/common';
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
		const tableName = 'Notifications';
		this.dbInstance = dynamoose.model<NotificationSettings>(
			tableName,
			NotificationSettingsSchema
		);
		this.dbUserInstance = dynamoose.model<User>('Users', UserSchema);
	}
	async getUserNotificationSettings(userId: string) {
		const settings = await this.dbInstance.get(userId);
		return settings;
	}

	async toggleNotifications(userId: string, isActive: boolean) {
		const settings = await this.dbInstance.get(userId);
		settings.NotificationsActive = isActive;
		settings.MuteUntil = 0;
		await settings.save();
		return convertToCamelCase(settings);
	}

	async muteNotifications(userId: string, duration: string) {
		const settings = await this.dbInstance.get(userId);

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
				throw new BadRequestException('Invalid mute duration');
		}

		settings.MuteUntil = MuteUntil;
		settings.NotificationsActive = false;
		await settings.save();
		return convertToCamelCase(settings);
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
