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
	async findAll(belongs?: string, types?: Array<string>) {
		let modules;

		if (belongs) {
			modules = await this.dbInstance.query('Belongs').eq(belongs).exec();
		} else {
			modules = await this.dbInstance.scan().exec();
		}

		modules.sort(
			(
				a: { Index: number; SubIndex: number },
				b: { Index: number; SubIndex: number }
			) => {
				if (a.Index === b.Index) {
					return a.SubIndex - b.SubIndex;
				}
				return a.Index - b.Index;
			}
		);

		if (types && types.length > 0) {
			modules = modules.filter(module => types.includes(module.Belongs));
		}
		return modules.map(this.mapModuleToResponse);
	}

	private mapModuleToResponse(module: Module) {
		return {
			id: module.Id,
			belongs: module.Belongs,
			index: module.Index,
			subIndex: module.SubIndex,
			description: module.Description,
			createDate: module.CreateDate,
			updateDate: module.UpdateDate,
		};
	}
}
