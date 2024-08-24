import * as dynamoose from 'dynamoose';
import { Model } from 'dynamoose/dist/Model';
import { Injectable } from '@nestjs/common';

import { ModuleSchema } from './entities/module.schema';
import { Module } from './entities/module.entity';

@Injectable()
export class ModuleService {
	private readonly dbInstance: Model<Module>;

	constructor() {
		const tableName = 'Modules';
		this.dbInstance = dynamoose.model<Module>(tableName, ModuleSchema, {
			create: false,
			waitForActive: false,
		});
	}
	async findAll(): Promise<Module[]> {
		const modules = await this.dbInstance
			.scan()
			.attributes(['Id', 'Description'])
			.exec();
		return modules;
	}
}
