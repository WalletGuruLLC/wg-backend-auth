import {
	Body,
	Controller,
	Delete,
	Get,
	Query,
	HttpException,
	HttpStatus,
	Param,
	Patch,
	Post,
	UseGuards,
	UsePipes,
	ValidationPipe,
	ValidationError,
	Put,
} from '@nestjs/common';
import {
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

const customValidationPipe = new ValidationPipe({
	exceptionFactory: (errors: ValidationError[]) => {
		const message = errors.map(
			error =>
				`${error.property} has wrong value ${error.value}, ${Object.values(
					error.constraints
				).join(', ')}`
		);
		return new HttpException(
			{ customCode: 'WGE0025', ...errorCodes.WGE0025, message },
			HttpStatus.BAD_REQUEST
		);
	},
});

@ApiTags('role')
@Controller('api/v1/roles')
export class RoleController {
	constructor(private readonly roleService: RoleService) {}

	@UseGuards(CognitoAuthGuard)
	@Post()
	@UsePipes(customValidationPipe)
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
			throw new HttpException(
				{
					customCode: 'WGE0025',
					...errorCodes.WGE0025,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Get()
	@ApiOkResponse({
		description: 'Roles have been successfully retrieved.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async findAll(
		@Query('providerId') providerId?: string,
		@Query('page') page = 1,
		@Query('items') items = 10
	) {
		try {
			const roles = await this.roleService.findAll(
				providerId,
				Number(page),
				Number(items)
			);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGS0031',
				customMessage: successCodes.WGS0031?.description,
				customMessageEs: successCodes.WGS0031?.descriptionEs,
				data: roles,
			};
		} catch (error) {
			//TODO: throw error only if no roles are found
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0032',
					customMessage: errorCodes.WGE0032?.description,
					customMessageEs: errorCodes.WGE0032?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}
	@UseGuards(CognitoAuthGuard)
	@Get(':id')
	@ApiOkResponse({
		description: 'The role has been successfully retrieved.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async findOne(@Param('id') id: string) {
		try {
			const role = await this.roleService.findOne(id);
			if (!role) {
				throw new HttpException('Role not found', HttpStatus.NOT_FOUND);
			}
			return {
				statusCode: HttpStatus.OK,
				message: 'Role found',
				data: role,
			};
		} catch (error) {
			if (error.status === HttpStatus.NOT_FOUND) {
				throw error; // Re-throw 404 errors as they are
			}
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					message: `Error retrieving role: ${error.message}`,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Patch(':id')
	@ApiOkResponse({
		description: 'The role has been successfully updated.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async update(@Param('id') id: string, @Body() updateRoleDto: UpdateRoleDto) {
		try {
			const role = await this.roleService.update(id, updateRoleDto);
			return {
				statusCode: HttpStatus.OK,
				message: 'Role updated successfully',
				data: role,
			};
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					message: `Error updating role: ${error.message}`,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Delete(':id')
	@ApiOkResponse({
		description: 'The role has been successfully deleted.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async remove(@Param('id') id: string) {
		try {
			await this.roleService.remove(id);
			return {
				statusCode: HttpStatus.OK,
				message: 'Role deleted successfully',
			};
		} catch (error) {
			if (error.message === 'Role not found in database') {
				throw new HttpException(
					{
						statusCode: HttpStatus.NOT_FOUND,
						message: error.message,
					},
					HttpStatus.NOT_FOUND
				);
			} else {
				throw new HttpException(
					{
						statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
						message: `Error deleting role: ${error.message}`,
					},
					HttpStatus.INTERNAL_SERVER_ERROR
				);
			}
		}
	}

	@ApiOperation({ summary: 'Crear un nuevo nivel de acceso para un módulo' })
	@ApiParam({ name: 'roleId', description: 'ID del rol', type: String })
	@ApiParam({ name: 'moduleId', description: 'ID del módulo', type: String })
	@ApiBody({ schema: { example: { accessLevel: 11 } } })
	@ApiResponse({
		status: 201,
		description: 'Nivel de acceso creado con éxito.',
	})
	@ApiResponse({ status: 404, description: 'Role not found' })
	@Post('create/:roleId/:moduleId')
	async createAccessLevel(
		@Param('roleId') roleId: string,
		@Param('moduleId') moduleId: string,
		@Body('accessLevel') accessLevel: number
	) {
		const role = await this.roleService.findOne(roleId);
		if (!role) {
			throw new HttpException(
				{
					statusCode: HttpStatus.NOT_FOUND,
					message: 'Role not found',
				},
				HttpStatus.NOT_FOUND
			);
		}

		return this.roleService.createAccessLevel(role?.Id, moduleId, accessLevel);
	}

	@ApiOperation({ summary: 'Editar un nivel de acceso para un módulo' })
	@ApiParam({ name: 'roleId', description: 'ID del rol', type: String })
	@ApiParam({ name: 'moduleId', description: 'ID del módulo', type: String })
	@ApiBody({ schema: { example: { accessLevel: 15 } } })
	@ApiResponse({
		status: 200,
		description: 'Nivel de acceso actualizado con éxito.',
	})
	@ApiResponse({
		status: 404,
		description: 'Role not found or Module not found in role',
	})
	@Put('edit/:roleId/:moduleId')
	async updateAccessLevel(
		@Param('roleId') roleId: string,
		@Param('moduleId') moduleId: string,
		@Body('accessLevel') accessLevel: number
	) {
		const role = await this.roleService.findOne(roleId);
		if (!role) {
			throw new HttpException(
				{
					statusCode: HttpStatus.NOT_FOUND,
					message: 'Role not found',
				},
				HttpStatus.NOT_FOUND
			);
		}

		if (!role.Modules || !role.Modules[moduleId]) {
			throw new HttpException(
				{
					statusCode: HttpStatus.NOT_FOUND,
					message: 'Module not found in role',
				},
				HttpStatus.NOT_FOUND
			);
		}

		return this.roleService.updateAccessLevel(role?.Id, moduleId, accessLevel);
	}

	@ApiOperation({ summary: 'Listar los niveles de acceso para un rol' })
	@ApiParam({ name: 'roleId', description: 'ID del rol', type: String })
	@ApiResponse({
		status: 200,
		description: 'Lista de niveles de acceso obtenida con éxito.',
	})
	@ApiResponse({ status: 404, description: 'Role not found' })
	@Get('list/:roleId')
	async listAccessLevels(@Param('roleId') roleId: string) {
		const role = await this.roleService.findOne(roleId);
		if (!role) {
			throw new HttpException(
				{
					statusCode: HttpStatus.NOT_FOUND,
					message: 'Role not found',
				},
				HttpStatus.NOT_FOUND
			);
		}

		return this.roleService.listAccessLevels(role?.Id);
	}
}
