import {
	Body,
	Controller,
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
	Req,
} from '@nestjs/common';
import { ProviderService } from '../service/provider.service';
import {
	ChangeStatusProviderDto,
	CreateProviderDto,
	UpdateProviderDto,
} from '../dto/provider';
import * as Sentry from '@sentry/nestjs';
import {
	ApiBearerAuth,
	ApiBody,
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
import { convertToCamelCase } from '../../../utils/helpers/convertCamelCase';

@ApiTags('provider')
@ApiBearerAuth('JWT')
@Controller('api/v1/providers')
export class ProviderController {
	constructor(private readonly providerService: ProviderService) {}

	@UseGuards(CognitoAuthGuard)
	@Post()
	@UsePipes(ValidationPipe)
	@ApiOperation({ summary: 'Create a new provider' })
	@ApiBody({
		description: 'The provider creation data',
		required: true,
		schema: {
			example: {
				name: 'Provider Name',
				description: 'Provider Description',
				email: 'provider@example.com',
				phone: '+123456789',
				einNumber: '12-3456789',
				country: 'Argentina',
				city: 'Balvanera',
				zipCode: '59569',
				companyAddress: 'Company Address test',
				walletAddress: '',
				contactInformation: 'Contact Info test',
			},
		},
	})
	@ApiResponse({
		status: 201,
		description: 'Provider created successfully.',
		schema: {
			example: {
				statusCode: 201,
				customCode: 'WGS0077',
				customMessage: 'Provider created successfully.',
				customMessageEs: 'Proveedor creado con éxito.',
				data: {
					Name: 'Provider Name',
					Description: 'Provider description',
					Email: 'provider@example.com',
					Phone: '+123456789',
					EINNumber: '12-3456789',
					Country: 'Argentina',
					City: 'Balvanera',
					ZipCode: '59569',
					CompanyAddress: 'Company Address test',
					WalletAddress: 'test wallet address',
					ContactInformation: 'Contact Info test',
					CreateDate: 1725592379481,
					UpdateDate: 1725592379481,
					Id: '4fef9ad1-1dba-4e65-976a-1bea78043e66',
				},
			},
		},
	})
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
	@ApiOperation({
		summary:
			'Retrieve a list of providers with pagination and optional search.',
	})
	@ApiOkResponse({
		status: 200,
		description: 'Providers retrieved successfully.',
		schema: {
			example: {
				statusCode: 200,
				customCode: 'WGE0073',
				customMessage: 'Providers retrieved successfully.',
				customMessageEs: 'Proveedores recuperados con éxito.',
				data: {
					providers: [
						{
							id: '123',
							name: 'Provider Name',
							description: 'Provider Description',
							email: 'provider@example.com',
							phone: '+123456789',
							einNumber: '12-3456789',
							country: 'Argentina',
							city: 'Balvanera',
							zipCode: '59569',
							companyAddress: 'Company Address',
							walletAddress: '',
							logo: 'https://example.com/logo.png',
							contactInformation: 'Contact Info',
						},
					],
					currentPage: 1,
					total: 1,
					totalPages: 1,
				},
			},
		},
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
	@ApiResponse({
		status: 200,
		description: 'Provider found.',
		schema: {
			example: {
				statusCode: 200,
				customCode: 'WGE0074',
				customMessage: 'Provider found successfully.',
				customMessageEs: 'Proveedor encontrado con éxito.',
				data: {
					id: '123',
					name: 'Provider Name',
					description: 'Provider Description',
					email: 'provider@example.com',
					phone: '+123456789',
					einNumber: '12-3456789',
					country: 'Argentina',
					city: 'Balvanera',
					zipCode: '59569',
					companyAddress: 'Company Address',
					walletAddress: '',
					logo: 'https://example.com/logo.png',
					contactInformation: 'Contact Info',
				},
			},
		},
	})
	@ApiResponse({ status: 404, description: 'Provider not found.' })
	async findOne(@Param('id') id: string) {
		try {
			const provider = await this.providerService.findOne(id);
			if (!provider) {
				return {
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0040',
				};
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
	@ApiBody({
		description: 'Data to update the provider.',
		schema: {
			example: {
				name: 'Updated Provider Name',
				description: 'Updated Description',
				email: 'updated@example.com',
				phone: '+123456789',
				einNumber: '12-3456789',
				country: 'Argentina',
				city: 'Balvanera',
				zipCode: '59569',
				companyAddress: 'Updated Address',
				walletAddress: '',
				contactInformation: 'Updated Contact Info',
			},
		},
	})
	@ApiResponse({ status: 200, description: 'Provider updated successfully.' })
	@ApiResponse({ status: 500, description: 'Error updating provider.' })
	async update(
		@Param('id') id: string,
		@Body() updateProviderDto: UpdateProviderDto
	) {
		try {
			const providerFind = await this.providerService.findOne(id);
			if (!providerFind) {
				return {
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0040',
				};
			}
			const provider = await this.providerService.update(id, updateProviderDto);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGS0034',
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
	@ApiOperation({ summary: 'Activate or desactivate an existing provider' })
	@ApiParam({ name: 'id', description: 'ID of the provider', type: String })
	@ApiBody({
		description: 'Status change data for the provider.',
		schema: {
			example: {
				active: false,
			},
		},
	})
	@ApiResponse({
		status: 200,
		description: 'Provider status updated successfully.',
	})
	@ApiResponse({ status: 500, description: 'Error updating provider status.' })
	async activeInactiveProvider(
		@Param('id') id: string,
		@Body() changeStatusProvider: ChangeStatusProviderDto
	) {
		try {
			const providerFind = await this.providerService.findOne(id);
			if (!providerFind) {
				return {
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0040',
				};
			}
			const provider = await this.providerService.activeInactiveProvider(
				id,
				changeStatusProvider
			);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGS0034',
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

	@UseGuards(CognitoAuthGuard)
	@Get('list/users/:id?')
	@ApiOperation({
		summary:
			'Retrieve a list of users from the service provider with pagination and optional search.',
	})
	@ApiOkResponse({
		status: 200,
		description: 'Users retrieved successfully.',
		schema: {
			example: {
				statusCode: 200,
				customCode: 'WGE0073',
				customMessage: 'Users retrieved successfully.',
				customMessageEs: 'Usuários recuperados con éxito.',
				data: {
					providers: [
						{
							id: '123',
							name: 'Provider Name',
							description: 'Provider Description',
							email: 'provider@example.com',
							phone: '+123456789',
							einNumber: '12-3456789',
							country: 'Argentina',
							city: 'Balvanera',
							zipCode: '59569',
							companyAddress: 'Company Address',
							walletAddress: '',
							logo: 'https://example.com/logo.png',
							contactInformation: 'Contact Info',
						},
					],
					currentPage: 1,
					total: 1,
					totalPages: 1,
				},
			},
		},
	})
	@ApiForbiddenResponse({ status: 403, description: 'Access forbidden.' })
	async findAllUsers(
		@Query() getProvidersDto: GetProvidersDto,
		@Req() req,
		@Res() res,
		@Param('id') providerId?: string
	) {
		try {
			const userRequest = req.user?.UserAttributes;

			const userProvider = await this.providerService.findAllUsers(
				getProvidersDto,
				userRequest,
				providerId
			);
			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0073',
				customMessage: successCodes.WGE0073?.description,
				customMessageEs: successCodes.WGE0073?.descriptionEs,
				data: convertToCamelCase(userProvider),
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
}
