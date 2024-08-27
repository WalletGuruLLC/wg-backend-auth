import * as dynamoose from 'dynamoose';
import { Model } from 'dynamoose/dist/Model';
import { Injectable } from '@nestjs/common';

import { SettingSchema } from './entities/setting.schema';
import { Setting } from './entities/setting.entity';
import { convertToCamelCase } from '../../utils/helpers/convertCamelCase';

@Injectable()
export class SettingService {
	private readonly dbInstance: Model<Setting>;

	constructor() {
		const tableName = 'Settings';
		this.dbInstance = dynamoose.model<Setting>(tableName, SettingSchema, {
			create: true,
			waitForActive: false,
		});
	}
	async findAll(belongs: string) {
		const records = [
			{
				Id: 'SWG001',
				Belongs: 'app',
				Key: 'terms-condition',
				Value: 'https://www.mywalletguru.com/',
			},
			{
				Id: 'SWG002',
				Belong: 'app',
				Key: 'privacy-police',
				Value: 'https://www.mywalletguru.com/',
			},
		];

		for (const record of records) {
			await this.dbInstance.create(record);
		}

		let settings;
		if (belongs) {
			settings = await this.dbInstance.query('Belongs').eq(belongs).exec();
		} else {
			settings = await this.dbInstance.scan().exec();
		}

		return convertToCamelCase(settings);
	}
}
