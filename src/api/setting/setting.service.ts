import * as dynamoose from 'dynamoose';
import { Model } from 'dynamoose/dist/Model';
import { Injectable } from '@nestjs/common';

import { SettingSchema } from './entities/setting.schema';
import { Setting } from './entities/setting.entity';
import { convertToCamelCase } from 'src/utils/helpers/convertCamelCase';
import { UpdateSettingsDto } from './dto/update-settings.dto';

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

	async findOneById(id: string) {
		try {
			const users = await this.dbInstance.query('Id').eq(id).exec();
			return convertToCamelCase(users[0]);
		} catch (error) {
			throw new Error(`Error retrieving user: ${error.message}`);
		}
	}

	async update(id: string, updateSettings: UpdateSettingsDto) {
		try {
			const settings = await this.findOneById(id);

			if (!settings) {
				throw new Error(`Setting with ID ${id} not found.`);
			}

			const result = await this.dbInstance.update({
				Id: id,
				Value: updateSettings.value,
			});

			return convertToCamelCase(result);
		} catch (error) {
			throw new Error(`Error updating settings: ${error.message}`);
		}
	}
}
