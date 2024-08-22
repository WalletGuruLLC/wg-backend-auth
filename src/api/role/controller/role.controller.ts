import {
	Body,
	Controller,
	Delete,
	Get,
	Query,
	HttpException,
	HttpStatus,
	Param,
	Put,
	Post,
	UseGuards,
	UsePipes,
} from '@nestjs/common';
import {
	ApiCreatedResponse,
	ApiForbiddenResponse,
	ApiOkResponse,
	ApiTags,
} from '@nestjs/swagger';

import { errorCodes, successCodes } from '../../../utils/constants';
import { CreateRoleDto } from '../dto/create-role.dto';
import { UpdateRoleDto } from '../dto/update-role.dto';
import { RoleService } from '../service/role.service';
import { CognitoAuthGuard } from '../../user/guard/cognito-auth.guard';
import { customValidationPipe } from '../../validation.pipe';

@ApiTags('role')
@Controller('api/v1/roles')
export class RoleController {
	constructor(private readonly roleService: RoleService) {}

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
