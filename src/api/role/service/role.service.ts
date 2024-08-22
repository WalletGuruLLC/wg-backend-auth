import * as dynamoose from 'dynamoose';
import { Model } from 'dynamoose/dist/Model';
import { Injectable, HttpException, HttpStatus } from '@nestjs/common';

import { RoleSchema } from '../entities/role.schema';
import { errorCodes } from '../../../utils/constants';
import { Role } from '../entities/role.entity';
import { CreateRoleDto } from '../dto/create-role.dto';
import { UpdateRoleDto } from '../dto/update-role.dto';

@Injectable()
export class RoleService {
	private readonly dbInstance: Model<Role>;

	constructor() {
		const tableName = 'roles';
		this.dbInstance = dynamoose.model<Role>(tableName, RoleSchema, {
			create: false,
			waitForActive: false,
		});
	}

	async create(createRoleDto: CreateRoleDto): Promise<Role> {
		const role = {
			Name: createRoleDto.name,
			Description: createRoleDto.description,
			ProviderId: createRoleDto.providerId,
		};

		const savedRole = await this.dbInstance.create(role);
		return savedRole;
	}

	async findAll(
		providerId?: string,
		page = 1,
		items = 10
	): Promise<{ roles: Role[]; total: number }> {
		const skip = (page - 1) * items;
		let dbQuery;

		if (providerId) {
			dbQuery = this.dbInstance
				.query('ProviderId')
				.eq(providerId)
				.using('ProviderIdIndex');
		} else {
			dbQuery = this.dbInstance.scan();
		}

		const roles = await dbQuery.exec();

		if (roles.length === 0) {
			throw new Error();
		}

		roles.sort((a, b) => {
			if (a.Active === b.Active) {
				return a.Name.localeCompare(b.Name);
			}
			return a.Active ? -1 : 1;
		});

		const total = roles.length;

		const paginatedRoles = roles.slice(skip, skip + items);

		return { roles: paginatedRoles, total };
	}

	async update(id: string, updateRoleDto: UpdateRoleDto): Promise<Role> {
		await this.findOne(id);

		return await this.dbInstance.update({
			Id: id,
			Name: updateRoleDto.name,
			Description: updateRoleDto.description,
		});
	}

	private async findOne(id: string): Promise<Role> {
		const role = await this.dbInstance.get(id);
		if (!role) {
			throw new HttpException(
				{
					customCode: 'WGE0027',
					...errorCodes.WGE0027,
				},
				HttpStatus.NOT_FOUND
			);
		}
		return role;
	}

	async remove(id: string): Promise<void> {
		await this.dbInstance.delete(id);
	}
}
