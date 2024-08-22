import * as dynamoose from 'dynamoose';
import { Model } from 'dynamoose/dist/Model';
import { Injectable } from '@nestjs/common';

import { RoleSchema } from '../entities/role.schema';
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

	async findOne(id: string): Promise<Role> {
		return this.dbInstance.get(id) as Promise<Role>;
	}

	async update(id: string, updateRoleDto: UpdateRoleDto): Promise<Role> {
		return this.dbInstance.update(
			{ Id: id },
			updateRoleDto as Partial<Role>
		) as Promise<Role>;
	}

	async remove(id: string): Promise<void> {
		await this.dbInstance.delete(id);
	}

	async createAccessLevel(
		roleId: string,
		moduleId: string,
		accessLevel: number
	) {
		const role = await this.findOne(roleId);

		if (!role.Modules) {
			role.Modules = {};
		}

		role.Modules[moduleId] = accessLevel;

		return await this.dbInstance.update(
			{ Id: roleId },
			{ Modules: role.Modules }
		);
	}

	async updateAccessLevel(
		roleId: string,
		moduleId: string,
		accessLevel: number
	) {
		const role = await this.dbInstance.get(roleId);
		role.Modules[moduleId] = accessLevel;
		return await role.save();
	}

	async listAccessLevels(roleId: string) {
		const role = await this.dbInstance.get(roleId);
		return role.Modules;
	}
}
