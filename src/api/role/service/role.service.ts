import { Injectable } from '@nestjs/common';
import { RoleModel, RoleDocument } from '../entities/role.entity';
import { CreateRoleDto, UpdateRoleDto } from '../dto/role';

@Injectable()
export class RoleService {
	async create(createRoleDto: CreateRoleDto): Promise<RoleDocument> {
		const role = new RoleModel(createRoleDto);
		return role.save() as Promise<RoleDocument>;
	}

	async findAll(): Promise<RoleDocument[]> {
		const scanResults = await RoleModel.scan().exec();
		return scanResults as unknown as RoleDocument[];
	}

	async findOne(id: string): Promise<RoleDocument> {
		return RoleModel.get(id) as Promise<RoleDocument>;
	}

	async update(
		id: string,
		updateRoleDto: UpdateRoleDto
	): Promise<RoleDocument> {
		return RoleModel.update({ id }, updateRoleDto) as Promise<RoleDocument>;
	}

	async remove(id: string): Promise<void> {
		await RoleModel.delete(id);
	}
}
