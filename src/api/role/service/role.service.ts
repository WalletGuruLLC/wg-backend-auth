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

	async findAll(): Promise<Role[]> {
		const roles = await this.dbInstance.scan().exec();
		return roles;
	}

	async findOne(id: string): Promise<Role> {
		return this.dbInstance.get(id) as Promise<Role>;
	}

	async update(id: string, updateRoleDto: UpdateRoleDto): Promise<Role> {
		return this.dbInstance.update({ id }, updateRoleDto) as Promise<Role>;
	}

	async remove(id: string): Promise<void> {
		await this.dbInstance.delete(id);
	}
}
