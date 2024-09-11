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
import { User } from '../../user/entities/user.entity';
import { UserSchema } from '../../user/entities/user.schema';
import { Provider } from '../../provider/entities/provider.entity';
import { ProviderSchema } from '../../provider/entities/provider.schema';
import { ScanResponse } from 'dynamoose/dist/DocumentRetriever';

@Injectable()
export class RoleService {
	private readonly dbInstance: Model<Role>;
	private dbUserInstance: Model<User>;
	private dbProviderInstance: Model<Provider>;

	constructor(private readonly providerService: ProviderService) {
		const tableName = 'Roles';
		this.dbInstance = dynamoose.model<Role>(tableName, RoleSchema, {
			create: false,
			waitForActive: false,
		});
		this.dbUserInstance = dynamoose.model<User>('Users', UserSchema);
		this.dbProviderInstance = dynamoose.model<Provider>(
			'Providers',
			ProviderSchema
		);
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
		search = '',
		orderBy = 'Name',
		ascending = true
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
			if (a.Active !== b.Active) {
				return a.Active ? -1 : 1;
			}
			if (a[orderBy] === b[orderBy]) {
				return 0;
			}
			if (ascending) {
				return a[orderBy] > b[orderBy] ? 1 : -1;
			} else {
				return a[orderBy] < b[orderBy] ? 1 : -1;
			}
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

	async findAllActive(providerId?: string, orderBy = 'Name', ascending = true) {
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

		let roles = [];
		let result;
		do {
			result = await docClient.scan(params).promise();
			roles = roles.concat(result.Items || []);
			params.ExclusiveStartKey = result.LastEvaluatedKey;
		} while (result.LastEvaluatedKey);

		if (roles.length === 0) {
			throw new Error('No active roles found.');
		}

		roles.sort((a, b) => {
			if (a.Active !== b.Active) {
				return a.Active ? -1 : 1;
			}
			if (a[orderBy] === b[orderBy]) {
				return 0;
			}
			if (ascending) {
				return a[orderBy] > b[orderBy] ? 1 : -1;
			} else {
				return a[orderBy] < b[orderBy] ? 1 : -1;
			}
		});

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

	async listRoles(user?: string, providerId?: string, page = 1, items = 10) {
		//IF USERS TYPE PLATFORM AND providerId NULL/UNDEFINED THAN RETURN EMPTY ONES OK
		//IF USERS TYPE PLATFORM AND providerId NOT NULL BRING THAN RETURN THE MATCHES OK
		//IF USERS TYPE PROVIDER SEARCH THE PROVIDER ID FROM TOKEN AND RETURN THE MATCHES OK
		//IF USERS TYPE WALLET RETURN AN ERROR OK
		const userConverted = user as unknown as { Name: string; Value: string }[];
		const email = userConverted[0]?.Value; // Safely extract Value

		if (!email) {
			throw new Error('E-mail must not be undefined!');
		}

		const users = await this.dbUserInstance.query('Email').eq(email).exec();

		if (users.length === 0) {
			throw new Error('User not found');
		}

		const userType = users[0].Type;

		const offset = (page - 1) * items;

		let roles = [];
		let total = 0;

		if (userType === 'PLATFORM') {
			let rolesQuery: ScanResponse<Role>;

			if (providerId === undefined || providerId === null) {
				rolesQuery = await this.dbInstance
					.scan('ProviderId')
					.eq('EMPTY')
					.exec();
			} else {
				rolesQuery = await this.dbInstance
					.scan('ProviderId')
					.eq(providerId)
					.exec();
			}

			roles = rolesQuery
				.map(item => item.toJSON())
				.sort((a, b) => {
					if (a.Active === b.Active) {
						return a.Description.localeCompare(b.Description);
					}
					return a.Active === true ? -1 : 1;
				});

			roles = roles.slice(offset, offset + items);
			total = roles.length;
		}

		if (userType === 'PROVIDER') {
			const providersQuery = await this.dbProviderInstance
				.scan('Id')
				.eq(users[0].ServiceProviderId)
				.exec();

			roles = providersQuery
				.map(item => item.toJSON())
				.sort((a, b) => {
					if (a.Active === b.Active) {
						return a.Description.localeCompare(b.Description);
					}
					return a.Active === true ? -1 : 1;
				});

			roles = roles.slice(offset, offset + items);
			total = roles.length;
		}

		if (userType === 'WALLET') {
			throw new Error('Invalid user type: wallet');
		}

		return {
			roles,
			total,
		};
	}
}
