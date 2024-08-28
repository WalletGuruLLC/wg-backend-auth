import * as dynamoose from 'dynamoose';
import { Model } from 'dynamoose/dist/Model';
import { Injectable } from '@nestjs/common';

import { SettingSchema } from './entities/setting.schema';
import { Setting } from './entities/setting.entity';

@Injectable()
export class SettingService {
	private readonly dbInstance: Model<Setting>;

	constructor() {
		const tableName = 'Settings';
		this.dbInstance = dynamoose.model<Setting>(tableName, SettingSchema, {
			create: false,
			waitForActive: false,
		});
	}
	async findAll(belongs: string) {
		let settings;
		if (belongs) {
			settings = await this.dbInstance.query('Belongs').eq(belongs).exec();
		} else {
			settings = await this.dbInstance.scan().exec();
		}

		return settings.map(this.mapSettingToResponse);
	}

	private mapSettingToResponse(setting: Setting) {
		return {
			id: setting.Id,
			belongs: setting.Belongs,
			key: setting.Key,
			value: setting.Value,
			createDate: setting.CreateDate,
			updateDate: setting.UpdateDate,
		};
	}
}
