import { convertToCamelCase } from 'src/utils/helpers/convertCamelCase';
import {
	Body,
	Controller,
	Get,
	Query,
	HttpException,
	HttpStatus,
	Param,
	Put,
	Patch,
	Post,
	UseGuards,
	UsePipes,
	Res,
	Req,
} from '@nestjs/common';
import {
	ApiBearerAuth,
	ApiBody,
	ApiCreatedResponse,
	ApiForbiddenResponse,
	ApiOkResponse,
	ApiOperation,
	ApiParam,
	ApiResponse,
	ApiTags,
} from '@nestjs/swagger';

import { errorCodes, successCodes } from '../../../utils/constants';
import { CreateRoleDto } from '../dto/create-role.dto';
import { UpdateRoleDto } from '../dto/update-role.dto';
import { RoleService } from '../service/role.service';
import { CognitoAuthGuard } from '../../user/guard/cognito-auth.guard';
import { customValidationPipe } from '../../validation.pipe';
import * as Sentry from '@sentry/nestjs';
import { GetRolesDto } from '../dto/get-user.dto';
import { isNumberInRange } from 'src/utils/helpers/validateAccessLevel';
import { UserService } from 'src/api/user/service/user.service';
import { ProviderService } from 'src/api/provider/service/provider.service';

@ApiTags('role')
@Controller('api/v1/roles')
@ApiBearerAuth('JWT')
export class RoleController {
	constructor(
		private readonly roleService: RoleService,
		private readonly userService: UserService,
		private readonly providerService: ProviderService
	) {}

	@UseGuards(CognitoAuthGuard)
	@Post()
	@UsePipes(customValidationPipe('WGE0025', errorCodes.WGE0025))
	@ApiCreatedResponse({
		description: 'The role has been successfully created.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async create(@Body() createRoleDto: CreateRoleDto) {
		try {
			const role = await this.roleService.create(createRoleDto);
			return {
				statusCode: HttpStatus.CREATED,
				customCode: 'WGS0023',
				customMessage: successCodes.WGS0023?.description,
				customMessageEs: successCodes.WGS0023?.descriptionEs,
				data: role,
			};
		} catch (error) {
			if (
				error instanceof HttpException &&
				error.getStatus() === HttpStatus.INTERNAL_SERVER_ERROR
			) {
				throw new HttpException(
					{
						customCode: 'WGE0025',
						...errorCodes.WGE0025,
						message: error.message,
					},
					HttpStatus.INTERNAL_SERVER_ERROR
				);
			}
			throw error;
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Get()
	@ApiOkResponse({
		description: 'Roles have been successfully retrieved.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async findAllPaginated(
		@Query() getRolesDto: GetRolesDto,
		@Req() req,
		@Res() res
	) {
		try {
			const {
				providerId,
				page = 1,
				items = 10,
				search,
				orderBy,
				ascending,
			} = getRolesDto;

			const userInfo = req.user;
			const user = await this.userService.findOneByEmail(
				userInfo?.UserAttributes?.[0]?.Value
			);

			if (user?.type == 'PROVIDER') {
				const rolesServiceProvider = await this.roleService.listRoles(
					req.user?.UserAttributes,
					user?.serviceProviderId,
					Number(page),
					Number(items)
				);
				if (rolesServiceProvider) {
					return res.status(HttpStatus.OK).send({
						statusCode: HttpStatus.OK,
						customCode: 'WGE0114',
						data: convertToCamelCase(rolesServiceProvider),
					});
				}
			} else {
				const roles = await this.roleService.findAllPaginated(
					providerId,
					Number(page),
					Number(items),
					search,
					orderBy,
					ascending
				);
				return res.status(HttpStatus.OK).send({
					statusCode: HttpStatus.OK,
					customCode: 'WGS0031',
					data: roles,
				});
			}
		} catch (error) {
			Sentry.captureException(error);
			//TODO: throw error only if no roles are found
			throw new HttpException(
				{
					customCode: 'WGE0032',
					...errorCodes.WGE0032,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Get('active')
	@ApiOkResponse({
		description: 'Active roles have been successfully retrieved.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async findAllActive(@Req() req, @Query('providerId') providerId?: string) {
		try {
			const userInfo = req.user;
			const user = await this.userService.findOneByEmail(
				userInfo?.UserAttributes?.[0]?.Value
			);
			let providerIdValue = providerId;
			if (user?.type == 'PROVIDER') {
				providerIdValue = user?.serviceProviderId;
			}

			if (user?.type == 'PLATFORM' && !providerId) {
				providerIdValue = 'EMPTY';
			}

			const roles = await this.roleService.findAllActive(providerIdValue);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGS0031',
				customMessage: successCodes.WGS0031?.description,
				customMessageEs: successCodes.WGS0031?.descriptionEs,
				data: roles,
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					customCode: 'WGE0032',
					...errorCodes.WGE0032,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Get(':id')
	@ApiOkResponse({
		description: 'Role have been successfully retrieved.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async getRoleInfo(@Param('id') id: string) {
		try {
			const role = await this.roleService.findRole(id);
			if (!role) {
				throw new HttpException(
					{
						statusCode: HttpStatus.NOT_FOUND,
						customCode: 'WGE0046',
						customMessage: errorCodes.WGE0046?.description,
						customMessageEs: errorCodes.WGE0046?.descriptionEs,
					},
					HttpStatus.INTERNAL_SERVER_ERROR
				);
			}
			const roleInfo = await this.roleService.getRoleInfo(id);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGS0082',
				customMessage: successCodes.WGS0082?.description,
				customMessageEs: successCodes.WGS0082?.descriptionEs,
				data: roleInfo,
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					customCode: 'WGE0046',
					...errorCodes.WGE0046,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Put(':id')
	@UsePipes(customValidationPipe('WGE0026', errorCodes.WGE0026))
	@ApiOkResponse({
		description: 'The role has been successfully updated.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async update(@Param('id') id: string, @Body() updateRoleDto: UpdateRoleDto) {
		try {
			const role = await this.roleService.update(id, updateRoleDto);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGS0024',
				customMessage: successCodes.WGS0024?.description,
				customMessageEs: successCodes.WGS0024?.descriptionEs,
				data: role,
			};
		} catch (error) {
			Sentry.captureException(error);
			if (
				error instanceof HttpException &&
				error.getStatus() === HttpStatus.INTERNAL_SERVER_ERROR
			) {
				throw new HttpException(
					{
						customCode: 'WGE0026',
						...errorCodes.WGE0026,
					},
					HttpStatus.INTERNAL_SERVER_ERROR
				);
			}
			throw error;
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Patch(':id/toggle')
	@ApiOperation({ summary: 'Toggle the active status of a role' })
	@ApiParam({ name: 'id', description: 'ID of the role', type: String })
	@ApiResponse({
		status: 200,
		description: 'Role status toggled successfully.',
	})
	@ApiResponse({
		status: 404,
		description: 'Role not found.',
	})
	async toggle(@Param('id') id: string, @Req() req) {
		try {
			const userRequest = req.user?.UserAttributes;
			const role = await this.roleService.toggle(id, userRequest);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGS0024',
				customMessage: successCodes.WGS0024?.description,
				customMessageEs: successCodes.WGS0024?.descriptionEs,
				data: role,
			};
		} catch (error) {
			if (
				error instanceof HttpException &&
				error.getStatus() === HttpStatus.INTERNAL_SERVER_ERROR
			) {
				throw new HttpException(
					{
						customCode: 'WGE0026',
						...errorCodes.WGE0026,
					},
					HttpStatus.INTERNAL_SERVER_ERROR
				);
			}
			throw error;
		}
	}

	@UseGuards(CognitoAuthGuard)
	@ApiOperation({
		summary: 'Create or update a new access level for a module',
	})
	@ApiParam({ name: 'roleId', description: 'ID del rol', type: String })
	@ApiParam({ name: 'moduleId', description: 'ID del módulo', type: String })
	@ApiBody({
		schema: { example: { accessLevel: 11 } },
	})
	@ApiResponse({
		status: 201,
		description: 'Access level created successfully.',
	})
	@ApiResponse({ status: 404, description: 'Role or Module not found' })
	@Post('/access-level/:roleId/:moduleId')
	async createSimpleAccessLevel(
		@Param('roleId') roleId: string,
		@Param('moduleId') moduleId: string,
		@Body() body: { accessLevel: Record<string, number> },
		@Res() res
	) {
		try {
			const role = await this.roleService.findRole(roleId);
			if (!role) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0027',
				});
			}

			if (!body?.accessLevel) {
				return res.status(HttpStatus.PARTIAL_CONTENT).send({
					statusCode: HttpStatus.PARTIAL_CONTENT,
					customCode: 'WGE0134',
				});
			}

			const moduleExists = await this.roleService.validateModuleExists(
				moduleId
			);

			if (!moduleExists) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0131',
				});
			}

			if (!isNumberInRange(body.accessLevel)) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0049',
				});
			}

			await this.roleService.createOrUpdateAccessLevelModules(
				roleId,
				moduleId,
				body.accessLevel
			);

			const roleUpd = await this.roleService.getRoleInfo(roleId);

			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0141',
				data: convertToCamelCase(roleUpd),
			});
		} catch (error) {
			Sentry.captureException(error);
			return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send({
				statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
				customCode: 'WGE0134',
			});
		}
	}

	@UseGuards(CognitoAuthGuard)
	@ApiOperation({
		summary:
			'Create or update a new access level for a module for service providers',
	})
	@ApiParam({ name: 'roleId', description: 'ID del rol', type: String })
	@ApiParam({ name: 'moduleId', description: 'ID del módulo', type: String })
	@ApiBody({
		schema: { example: { accessLevel: 11, serviceProvider: 'provider1' } },
	})
	@ApiResponse({
		status: 201,
		description: 'Access level created successfully.',
	})
	@ApiResponse({ status: 404, description: 'Role or Module not found' })
	@Post('/module-access-level/:roleId/:moduleId')
	async createOrUpdateAccessLevel(
		@Param('roleId') roleId: string,
		@Param('moduleId') moduleId: string,
		@Body()
		body: { accessLevel: Record<string, number>; serviceProvider: string }, // Ajuste en Body para incluir serviceProvider
		@Res() res
	) {
		try {
			const role = await this.roleService.searchFindOneId(roleId);
			if (!role) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0027',
				});
			}

			if (!body.serviceProvider || !body?.accessLevel) {
				return res.status(HttpStatus.PARTIAL_CONTENT).send({
					statusCode: HttpStatus.PARTIAL_CONTENT,
					customCode: 'WGE0134',
				});
			}

			if (body.serviceProvider) {
				const serviceProv = await this.providerService.searchFindOneId(
					body.serviceProvider
				);
				if (!serviceProv) {
					return res.status(HttpStatus.NOT_FOUND).send({
						statusCode: HttpStatus.NOT_FOUND,
						customCode: 'WGE0040',
					});
				}
			}

			const moduleExists = await this.roleService.validateModuleExists(
				moduleId
			);

			if (!moduleExists) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0131',
				});
			}

			if (!isNumberInRange(body.accessLevel)) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0049',
				});
			}

			await this.roleService.createOrUpdateAccessLevel(
				roleId,
				body.serviceProvider,
				Number(body.accessLevel),
				moduleId
			);

			const roleUpd = await this.roleService.getRoleInfo(roleId);

			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0141',
				data: convertToCamelCase(roleUpd),
			});
		} catch (error) {
			console.log('error', error?.message);
			Sentry.captureException(error);
			return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send({
				statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
				customCode: 'WGE0134',
			});
		}
	}

	@UseGuards(CognitoAuthGuard)
	@ApiOperation({
		summary: 'Create or update a new access level',
	})
	@ApiParam({ name: 'roleId', description: 'ID del rol', type: String })
	@ApiParam({ name: 'moduleId', description: 'ID del módulo', type: String })
	@ApiBody({
		schema: { example: { accessLevel: 11, serviceProvider: 'provider1' } },
	})
	@ApiResponse({
		status: 201,
		description: 'Access level created successfully.',
	})
	@ApiResponse({ status: 404, description: 'Role or Module not found' })
	@Post('/general-access-level/:roleId/:moduleId')
	async createOrUpdateGeneralAccessLevel(
		@Param('roleId') roleId: string,
		@Param('moduleId') moduleId: string,
		@Body()
		body: { accessLevel?: Record<string, number>; serviceProvider: string },
		@Res() res
	) {
		try {
			const role = await this.roleService.searchFindOneId(roleId);
			if (!role) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0027',
				});
			}

			const moduleExists = await this.roleService.validateModuleExists(
				moduleId
			);

			if (!moduleExists) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0131',
				});
			}

			if (!isNumberInRange(body.accessLevel)) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0049',
				});
			}

			if (body.serviceProvider) {
				const serviceProv = await this.providerService.searchFindOneId(
					body.serviceProvider
				);
				if (!serviceProv) {
					return res.status(HttpStatus.NOT_FOUND).send({
						statusCode: HttpStatus.NOT_FOUND,
						customCode: 'WGE0040',
					});
				}

				await this.roleService.createOrUpdateAccessLevel(
					roleId,
					body.serviceProvider,
					Number(body.accessLevel),
					moduleId
				);

				const roleUpd = await this.roleService.getRoleInfo(roleId);

				return res.status(HttpStatus.OK).send({
					statusCode: HttpStatus.OK,
					customCode: 'WGE0141',
					data: convertToCamelCase(roleUpd),
				});
			} else {
				await this.roleService.createOrUpdateAccessLevelModules(
					roleId,
					moduleId,
					body.accessLevel
				);

				const roleUpd = await this.roleService.getRoleInfo(roleId);

				return res.status(HttpStatus.OK).send({
					statusCode: HttpStatus.OK,
					customCode: 'WGE0141',
					data: convertToCamelCase(roleUpd),
				});
			}
		} catch (error) {
			Sentry.captureException(error);
			return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send({
				statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
				customCode: 'WGE0134',
			});
		}
	}

	@UseGuards(CognitoAuthGuard)
	@ApiOperation({ summary: 'List access levels for a role by modules' })
	@ApiParam({ name: 'roleId', description: 'ID del rol', type: String })
	@ApiResponse({
		status: 200,
		description: 'Lista de niveles de acceso obtenida con éxito.',
	})
	@ApiResponse({ status: 404, description: 'Role not found' })
	@Get('/simple-access-level/:roleId')
	async listSimpleAccessLevels(@Param('roleId') roleId: string) {
		try {
			const role = await this.roleService.findRole(roleId);
			if (!role) {
				throw new HttpException(
					{
						customCode: 'WGE0033',
						...errorCodes.WGE0033,
					},
					HttpStatus.INTERNAL_SERVER_ERROR
				);
			}

			const modulos = await this.roleService.listAccessLevelsModules(role?.Id);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0081',
				customMessage: successCodes.WGE0081?.description,
				customMessageEs: successCodes.WGE0081?.descriptionEs,
				data: modulos,
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					customCode: 'WGE0037',
					...errorCodes.WGE0037,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@ApiOperation({
		summary: 'List access levels for a role with service providers',
	})
	@ApiParam({ name: 'roleId', description: 'ID del rol', type: String })
	@ApiResponse({
		status: 200,
		description: 'Lista de niveles de acceso obtenida con éxito.',
	})
	@ApiResponse({ status: 404, description: 'Role not found' })
	@Get('/access-level/:roleId')
	async listAccessLevels(@Param('roleId') roleId: string) {
		try {
			const role = await this.roleService.findRole(roleId);
			if (!role) {
				throw new HttpException(
					{
						customCode: 'WGE0033',
						...errorCodes.WGE0033,
					},
					HttpStatus.INTERNAL_SERVER_ERROR
				);
			}

			const modulos = await this.roleService.listAccessLevels(role?.Id);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0081',
				customMessage: successCodes.WGE0081?.description,
				customMessageEs: successCodes.WGE0081?.descriptionEs,
				data: modulos,
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					customCode: 'WGE0037',
					...errorCodes.WGE0037,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Get('list/providers/:id?') // '?' hace que el parámetro id sea opcional
	@ApiOperation({ summary: 'Retrieve roles from the Provider ID (optional)' })
	@ApiResponse({
		status: 200,
		description: 'Provider found.',
	})
	@ApiResponse({ status: 404, description: 'Provider not found.' })
	async listRoles(
		@Req() req,
		@Res() res,
		@Query() getRolesDto: GetRolesDto,
		@Param('id') providerId?: string
	) {
		try {
			const { page = 1, items = 10 } = getRolesDto;
			const user = req.user?.UserAttributes;

			const rolesServiceProvider = await this.roleService.listRoles(
				user,
				providerId,
				Number(page),
				Number(items)
			);
			if (rolesServiceProvider) {
				return res.status(HttpStatus.OK).send({
					statusCode: HttpStatus.OK,
					customCode: 'WGE0114',
					data: { roles: convertToCamelCase(rolesServiceProvider) },
				});
			}
		} catch (error) {
			Sentry.captureException(error);
			return res.status(HttpStatus.NOT_FOUND).send({
				statusCode: HttpStatus.NOT_FOUND,
				customCode: 'WGE0109',
			});
		}
	}
}
