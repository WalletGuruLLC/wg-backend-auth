import {
	Body,
	Controller,
	Delete,
	Get,
	HttpException,
	HttpStatus,
	Param,
	Patch,
	Post,
} from '@nestjs/common';
import {
	ApiCreatedResponse,
	ApiForbiddenResponse,
	ApiOkResponse,
	ApiTags,
} from '@nestjs/swagger';
import { CreateRoleDto, UpdateRoleDto } from '../dto/role';
import { RoleService } from '../service/role.service';

@ApiTags('role')
@Controller('api/v1/roles')
export class RoleController {
	constructor(private readonly roleService: RoleService) {}

	@Post()
	@ApiCreatedResponse({
		description: 'The role has been successfully created.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async create(@Body() createRoleDto: CreateRoleDto) {
		try {
			const role = await this.roleService.create(createRoleDto);
			return {
				statusCode: HttpStatus.CREATED,
				message: 'Role created successfully',
				data: role,
			};
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					message: `Error creating role: ${error.message}`,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@Get()
	@ApiOkResponse({
		description: 'Roles have been successfully retrieved.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async findAll() {
		try {
			const roles = await this.roleService.findAll();
			return {
				statusCode: HttpStatus.OK,
				message: 'Roles retrieved successfully',
				data: roles,
			};
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					message: `Error retrieving roles: ${error.message}`,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

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
}
