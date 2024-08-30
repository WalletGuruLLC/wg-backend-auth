import { DocumentClient } from 'aws-sdk/clients/dynamodb';
import * as dynamoose from 'dynamoose';
import { Model } from 'dynamoose/dist/Model';
import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { ProviderService } from '../../provider/service/provider.service';
import { RoleSchema } from '../entities/role.schema';
import { errorCodes } from '../../../utils/constants';
import { Role } from '../entities/role.entity';
import { CreateRoleDto } from '../dto/create-role.dto';
import { UpdateRoleDto } from '../dto/update-role.dto';

@Injectable()
export class RoleService {
	private readonly dbInstance: Model<Role>;

	constructor(private readonly providerService: ProviderService) {
		const tableName = 'Roles';
		this.dbInstance = dynamoose.model<Role>(tableName, RoleSchema, {
			create: false,
			waitForActive: false,
		});
	}

	async create(createRoleDto: CreateRoleDto) {
		if (createRoleDto.providerId !== 'EMPTY') {
			await this.providerService.findOne(createRoleDto.providerId);
		}

		const existingRole = await this.dbInstance
			.scan('Name')
			.eq(createRoleDto.name)
			.and()
			.filter('ProviderId')
			.eq(createRoleDto.providerId)
			.exec();

		if (existingRole.count > 0) {
			throw new HttpException(
				'Role with the same name already exists for this provider',
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}

		const role = {
			Name: createRoleDto.name,
			Description: createRoleDto.description,
			ProviderId: createRoleDto.providerId,
		};

		const savedRole = await this.dbInstance.create(role);
		return this.mapRoleToResponse(savedRole);
	}

	async findAllPaginated(
		providerId?: string,
		page = 1,
		items = 10,
		search = ''
	) {
		const docClient = new DocumentClient();

		const skip = (page - 1) * items;

		let params: DocumentClient.QueryInput | DocumentClient.ScanInput;
		if (providerId) {
			params = {
				TableName: 'Roles',
				IndexName: 'ProviderIdIndex',
				KeyConditionExpression: 'ProviderId = :providerId',
				ExpressionAttributeValues: {
					':providerId': providerId,
				},
			};
		} else {
			params = {
				TableName: 'Roles',
			};
		}

		let roles = [];
		let result;
		do {
			result = providerId
				? await docClient.query(params).promise()
				: await docClient.scan(params).promise();
			roles = roles.concat(result.Items || []);
			params.ExclusiveStartKey = result.LastEvaluatedKey;
		} while (result.LastEvaluatedKey);

		if (search) {
			const regex = new RegExp(search, 'i');
			roles = roles.filter(role => regex.test(role.Name));
		}

		roles.sort((a, b) => {
			if (a.Active === b.Active) {
				return a.Name.localeCompare(b.Name);
			}
			return a.Active ? -1 : 1;
		});

		const total = roles.length;

		const paginatedRoles = roles.slice(skip, skip + items);

		if (paginatedRoles.length === 0 && total > 0) {
			throw new Error(
				`No results found for page ${page} with ${items} items per page.`
			);
		}

		const transformedRoles = paginatedRoles.map(this.mapRoleToResponse);
		return { roles: transformedRoles, total };
	}

	async findAllActive(providerId?: string) {
		const docClient = new DocumentClient();

		const params: DocumentClient.ScanInput = {
			TableName: 'Roles',
			FilterExpression: 'Active = :active',
			ExpressionAttributeValues: {
				':active': true,
			},
		};

		if (providerId) {
			params.FilterExpression += ' AND ProviderId = :providerId';
			params.ExpressionAttributeValues[':providerId'] = providerId;
		}

		const result = await docClient.scan(params).promise();
		const roles = result.Items || [];

		return roles.map(this.mapRoleToResponse);
	}

	async update(id: string, updateRoleDto: UpdateRoleDto) {
		await this.findOne(id);

		const updatedRole = await this.dbInstance.update({
			Id: id,
			Name: updateRoleDto.name,
			Description: updateRoleDto.description,
		});
		return this.mapRoleToResponse(updatedRole);
	}

	async toggle(id: string) {
		const role = await this.findOne(id);

		role.Active = !role.Active;
		const updatedRole = await this.dbInstance.update(id, {
			Active: role.Active,
		});
		return this.mapRoleToResponse(updatedRole);
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

	async validateModuleExists(moduleId: string): Promise<boolean> {
		const docClient = new DocumentClient();

		const params = {
			TableName: 'Modules',
			Key: { Id: moduleId },
		};

		const result = await docClient.get(params).promise();
		return !!result.Item;
	}

	async createAccessLevel(
		roleId: string,
		moduleId: string,
		accessLevel: number
	) {
		const docClient = new DocumentClient();

		const params = {
			TableName: 'Roles',
			Key: { Id: roleId },
			UpdateExpression: 'SET #modules.#moduleId = :accessLevel',
			ExpressionAttributeNames: {
				'#modules': 'Modules',
				'#moduleId': moduleId,
			},
			ExpressionAttributeValues: {
				':accessLevel': accessLevel,
			},
			ReturnValues: 'ALL_NEW',
		};

		return await docClient.update(params).promise();
	}

	async updateAccessLevel(
		roleId: string,
		moduleId: string,
		accessLevel: number
	) {
		const docClient = new DocumentClient();

		const params = {
			TableName: 'Roles',
			Key: { Id: roleId },
			UpdateExpression: 'SET #modules.#moduleId = :accessLevel',
			ExpressionAttributeNames: {
				'#modules': 'Modules',
				'#moduleId': moduleId,
			},
			ExpressionAttributeValues: {
				':accessLevel': accessLevel,
			},
			ReturnValues: 'ALL_NEW',
		};

		await docClient.update(params).promise();
		return this.listAccessLevels(roleId);
	}

	async listAccessLevels(roleId: string) {
		const docClient = new DocumentClient();
		const params = {
			TableName: 'Roles',
			Key: { Id: roleId },
			ProjectionExpression: 'Modules',
		};

		const result = await docClient.get(params).promise();
		return result.Item?.Modules || {};
	}

	async getRoleInfo(roleId: string) {
		const docClient = new DocumentClient();
		const params = {
			TableName: 'Roles',
			Key: { Id: roleId },
		};

		const result = await docClient.get(params).promise();
		return result.Item;
	}

	async findRole(id: string): Promise<Role> {
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

	async getRolesByIds(ids) {
		const roles = await Promise.all(
			ids.map(async id => {
				try {
					const role = await this.findRole(id);
					return role;
				} catch (error) {
					if (error.status === HttpStatus.NOT_FOUND) {
						return id;
					}
					throw error;
				}
			})
		);

		return roles;
	}

	private mapRoleToResponse(role: Role) {
		return {
			id: role.Id,
			name: role.Name,
			description: role.Description,
			providerId: role.ProviderId,
			active: role.Active,
			modules: role.Modules,
			createDate: role.CreateDate,
			updateDate: role.UpdateDate,
		};
	}
}
