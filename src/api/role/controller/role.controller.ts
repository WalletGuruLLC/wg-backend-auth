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
} from '@nestjs/common';
import {
	ApiCreatedResponse,
	ApiForbiddenResponse,
	ApiOkResponse,
	ApiTags,
} from '@nestjs/swagger';

import { CreateRoleDto } from '../dto/create-role.dto';
import { UpdateRoleDto } from '../dto/update-role.dto';
import { RoleService } from '../service/role.service';
import { CognitoAuthGuard } from '../../user/guard/cognito-auth.guard';

@ApiTags('role')
@Controller('api/v1/roles')
export class RoleController {
	constructor(private readonly roleService: RoleService) {}

	@UseGuards(CognitoAuthGuard)
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
}
