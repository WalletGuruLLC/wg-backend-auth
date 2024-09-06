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
	Put,
	Query,
	Res,
	UseGuards,
	UsePipes,
	ValidationPipe,
	UploadedFile,
	UseInterceptors,
} from '@nestjs/common';
import { ProviderService } from '../service/provider.service';
import {
	CreateProviderDto,
	DeleteProviderDto,
	UpdateProviderDto,
} from '../dto/provider';
import * as Sentry from '@sentry/nestjs';
import {
	ApiBearerAuth,
	ApiForbiddenResponse,
	ApiOkResponse,
	ApiOperation,
	ApiParam,
	ApiResponse,
	ApiTags,
} from '@nestjs/swagger';
import { errorCodes, successCodes } from '../../../utils/constants';
import { GetProvidersDto } from '../dto/getProviderDto';
import { CognitoAuthGuard } from '../../user/guard/cognito-auth.guard';
import { FileInterceptor } from '@nestjs/platform-express';

@ApiTags('provider')
@ApiBearerAuth('JWT')
@Controller('api/v1/providers')
export class ProviderController {
	constructor(private readonly providerService: ProviderService) {}

	@UseGuards(CognitoAuthGuard)
	@Post()
	@UsePipes(ValidationPipe)
	@ApiOperation({ summary: 'Create a new provider' })
	@ApiResponse({ status: 201, description: 'Provider created successfully.' })
	@ApiResponse({ status: 500, description: 'Error creating provider.' })
	async create(@Body() createProviderDto: CreateProviderDto) {
		try {
			const provider = await this.providerService.create(createProviderDto);
			return {
				statusCode: HttpStatus.CREATED,
				customCode: 'WGS0077',
				customMessage: successCodes.WGS0077?.description,
				customMessageEs: successCodes.WGS0077?.descriptionEs,
				data: provider,
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0043',
					customMessage: errorCodes.WGE0043?.description,
					customMessageEs: errorCodes.WGE0043?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Get('')
	@ApiOperation({ summary: 'Retrieve a list of providers' })
	@ApiOkResponse({
		status: 200,
		description: 'Providers retrieved successfully.',
	})
	@ApiForbiddenResponse({ status: 403, description: 'Access forbidden.' })
	async findAll(@Query() getProvidersDto: GetProvidersDto, @Res() res) {
		try {
			const providers = await this.providerService.findAll(getProvidersDto);
			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0073',
				customMessage: successCodes.WGE0073?.description,
				customMessageEs: successCodes.WGE0073?.descriptionEs,
				data: providers,
			});
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

	@UseGuards(CognitoAuthGuard)
	@Get(':id')
	@ApiOperation({ summary: 'Retrieve a single provider by ID' })
	@ApiParam({ name: 'id', description: 'ID of the provider', type: String })
	@ApiResponse({ status: 200, description: 'Provider found.' })
	@ApiResponse({ status: 404, description: 'Provider not found.' })
	async findOne(@Param('id') id: string) {
		try {
			const provider = await this.providerService.findOne(id);
			if (!provider) {
				throw new HttpException('Provider not found', HttpStatus.NOT_FOUND);
			}
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0074',
				customMessage: successCodes?.WGE0074?.description,
				customMessageEs: successCodes.WGE0074?.descriptionEs,
				data: provider,
			};
		} catch (error) {
			Sentry.captureException(error);
			if (error.status === HttpStatus.NOT_FOUND) {
				throw error;
			}
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0040',
					customMessage: errorCodes?.WGE0040?.description,
					customMessageEs: errorCodes.WGE0040?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Put(':id')
	@UsePipes(ValidationPipe)
	@ApiOperation({ summary: 'Update an existing provider' })
	@ApiParam({ name: 'id', description: 'ID of the provider', type: String })
	@ApiResponse({ status: 200, description: 'Provider updated successfully.' })
	@ApiResponse({ status: 500, description: 'Error updating provider.' })
	async update(
		@Param('id') id: string,
		@Body() updateProviderDto: UpdateProviderDto
	) {
		try {
			const provider = await this.providerService.update(id, updateProviderDto);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0075',
				customMessage: successCodes?.WGE0075?.description,
				customMessageEs: successCodes.WGE0075?.descriptionEs,
				data: provider,
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0041',
					customMessage: errorCodes?.WGE0041?.description,
					customMessageEs: errorCodes.WGE0041?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Patch(':id')
	@UsePipes(ValidationPipe)
	@ApiOperation({ summary: 'Active or Inactive an existing provider' })
	@ApiParam({ name: 'id', description: 'ID of the provider', type: String })
	@ApiResponse({ status: 200, description: 'Provider updated successfully.' })
	@ApiResponse({ status: 500, description: 'Error updating provider.' })
	async changeStatus(
		@Param('id') id: string,
		@Body() deleteProviderDto: DeleteProviderDto
	) {
		try {
			const provider = await this.providerService.changeStatus(
				id,
				deleteProviderDto
			);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0075',
				customMessage: successCodes?.WGE0075?.description,
				customMessageEs: successCodes.WGE0075?.descriptionEs,
				data: provider,
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0041',
					customMessage: errorCodes?.WGE0041?.description,
					customMessageEs: errorCodes.WGE0041?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Delete(':id')
	@ApiOperation({ summary: 'Delete a provider by ID' })
	@ApiParam({ name: 'id', description: 'ID of the provider', type: String })
	@ApiResponse({ status: 200, description: 'Provider deleted successfully.' })
	@ApiResponse({ status: 404, description: 'Provider not found.' })
	@ApiResponse({ status: 500, description: 'Error deleting provider.' })
	async remove(@Param('id') id: string) {
		try {
			await this.providerService.remove(id);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0076',
				customMessage: successCodes?.WGE0076?.description,
				customMessageEs: successCodes.WGE0076?.descriptionEs,
			};
		} catch (error) {
			Sentry.captureException(error);
			if (error.message === 'Provider not found in database') {
				throw new HttpException(
					{
						statusCode: HttpStatus.NOT_FOUND,
						customCode: 'WGE0040',
						customMessage: errorCodes?.WGE0040?.description,
						customMessageEs: errorCodes.WGE0040?.descriptionEs,
					},
					HttpStatus.NOT_FOUND
				);
			} else {
				throw new HttpException(
					{
						statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
						customCode: 'WGE0042',
						customMessage: errorCodes?.WGE0042?.description,
						customMessageEs: errorCodes.WGE0042?.descriptionEs,
					},
					HttpStatus.INTERNAL_SERVER_ERROR
				);
			}
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Put('upload-image/:id')
	@UsePipes(ValidationPipe)
	@UseInterceptors(FileInterceptor('file'))
	@ApiOperation({ summary: 'Upload service provider image' })
	@ApiParam({ name: 'id', description: 'ID of the provider', type: String })
	@ApiResponse({ status: 200, description: 'Provider updated successfully.' })
	@ApiResponse({ status: 500, description: 'Error updating provider.' })
	async uploadImage(
		@Param('id') id: string,
		@UploadedFile() file: Express.Multer.File
	) {
		try {
			const provider = await this.providerService.uploadImage(id, file);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0075',
				customMessage: successCodes?.WGE0075?.description,
				customMessageEs: successCodes.WGE0075?.descriptionEs,
				data: provider,
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0041',
					customMessage: errorCodes?.WGE0041?.description,
					customMessageEs: errorCodes.WGE0041?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}
}
