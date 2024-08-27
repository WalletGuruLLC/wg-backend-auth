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
	UsePipes,
	ValidationPipe,
} from '@nestjs/common';
import { ProviderService } from '../service/provider.service';
import { CreateProviderDto, UpdateProviderDto } from '../dto/provider';
import * as Sentry from '@sentry/nestjs';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { errorCodes, successCodes } from 'src/utils/constants';

@ApiTags('provider')
@ApiBearerAuth('JWT')
@Controller('api/v1/providers')
export class ProviderController {
	constructor(private readonly providerService: ProviderService) {}

	@Post()
	@UsePipes(ValidationPipe)
	async create(@Body() createProviderDto: CreateProviderDto) {
		try {
			const provider = await this.providerService.create(createProviderDto);
			return {
				statusCode: HttpStatus.CREATED,
				message: 'Provider created successfully',
				data: provider,
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					message: `Error creating provider: ${error.message}`,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@Get()
	async findAll() {
		try {
			const providers = await this.providerService.findAll();
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0073',
				customMessage: successCodes.WGE0073?.description,
				customMessageEs: successCodes.WGE0073?.descriptionEs,
				data: providers,
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					statusCode: HttpStatus.FORBIDDEN,
					customCode: 'WGE0040',
					customMessage: errorCodes?.WGE0040?.description,
					customMessageEs: errorCodes.WGE0040?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@Get(':id')
	async findOne(@Param('id') id: string) {
		try {
			const provider = await this.providerService.findOne(id);
			if (!provider) {
				throw new HttpException('Provider not found', HttpStatus.NOT_FOUND);
			}
			return {
				statusCode: HttpStatus.OK,
				message: 'Provider found',
				data: provider,
			};
		} catch (error) {
			Sentry.captureException(error);
			if (error.status === HttpStatus.NOT_FOUND) {
				throw error; // Re-throw 404 errors as they are
			}
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					message: `Error retrieving provider: ${error.message}`,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@Patch(':id')
	@UsePipes(ValidationPipe)
	async update(
		@Param('id') id: string,
		@Body() updateProviderDto: UpdateProviderDto
	) {
		try {
			const provider = {}; //await this.providerService.update(id, updateProviderDto);
			return {
				statusCode: HttpStatus.OK,
				message: 'Provider updated successfully',
				data: provider,
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					message: `Error updating provider: ${error.message}`,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@Delete(':id')
	async remove(@Param('id') id: string) {
		try {
			await this.providerService.remove(id);
			return {
				statusCode: HttpStatus.OK,
				message: 'Provider deleted successfully',
			};
		} catch (error) {
			Sentry.captureException(error);
			if (error.message === 'Provider not found in database') {
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
						message: `Error deleting provider: ${error.message}`,
					},
					HttpStatus.INTERNAL_SERVER_ERROR
				);
			}
		}
	}
}
