import * as dynamoose from 'dynamoose';
import { Model } from 'dynamoose/dist/Model';
import { Injectable } from '@nestjs/common';

import { ModuleSchema } from './entities/module.schema';
import { Module } from './entities/module.entity';

@Injectable()
export class ModuleService {
	private readonly dbInstance: Model<Module>;

	constructor() {
		const tableName = 'modules';
		this.dbInstance = dynamoose.model<Module>(tableName, ModuleSchema, {
			create: false,
			waitForActive: false,
		});
	}
	async findAll() {
		const modules = await this.dbInstance.scan().exec();
		return modules.map(this.mapModuleToResponse);
	}

	private mapModuleToResponse(module: Module) {
		return {
			id: module.Id,
			description: module.Description,
			createDate: module.CreateDate,
			updateDate: module.UpdateDate,
		};
	}
}
