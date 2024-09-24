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
import { errorCodes } from '../../../utils/constants';
import { GetProvidersDto } from '../dto/getProviderDto';
import { CognitoAuthGuard } from '../../user/guard/cognito-auth.guard';
import { FileInterceptor } from '@nestjs/platform-express';
import { convertToCamelCase } from '../../../utils/helpers/convertCamelCase';
import { UpdateUserDto } from '../../user/dto/update-user.dto';
import { UserService } from 'src/api/user/service/user.service';
import { RoleService } from 'src/api/role/service/role.service';
import { CreateProviderPaymentParameterDTO } from '../dto/create-provider-payment-parameter.dto';
import { GetProviderPaymentParametersDTO } from '../dto/getProviderPaymentParametersDto';

@ApiTags('provider')
@ApiBearerAuth('JWT')
@Controller('api/v1/providers')
export class ProviderController {
	constructor(
		private readonly providerService: ProviderService,
		private readonly userService: UserService,
		private readonly roleService: RoleService
	) {}

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
	async create(
		@Body() createProviderDto: CreateProviderDto,
		@Res() res,
		@Req() req
	) {
		try {
			if (
				!createProviderDto?.name ||
				!createProviderDto?.einNumber ||
				!createProviderDto?.companyAddress ||
				!createProviderDto?.walletAddress
			) {
				return res.status(HttpStatus.PARTIAL_CONTENT).send({
					statusCode: HttpStatus.PARTIAL_CONTENT,
					customCode: 'WGE0134',
				});
			}

			if (createProviderDto?.email) {
				const providerFind = await this.providerService.searchFindOneEmail(
					createProviderDto?.email
				);
				if (providerFind) {
					return res.status(HttpStatus.FORBIDDEN).send({
						statusCode: HttpStatus.FORBIDDEN,
						customCode: 'WGE0133',
					});
				}
			}

			if (createProviderDto?.walletAddress) {
				const providerFind =
					await this.providerService.searchFindOneWalletAddress(
						createProviderDto?.walletAddress
					);
				if (providerFind) {
					return res.status(HttpStatus.FORBIDDEN).send({
						statusCode: HttpStatus.FORBIDDEN,
						customCode: 'WGE0138',
					});
				}
			}

			const userInfo = req.user;
			const userFind = await this.userService.findOneByEmail(
				userInfo?.UserAttributes?.[0]?.Value
			);
			const provider = await this.providerService.create(createProviderDto);
			await this.roleService.createOrUpdateAccessLevel(
				userFind?.roleId,
				provider?.Id,
				15,
				'SP95'
			);
			return res.status(HttpStatus.CREATED).send({
				statusCode: HttpStatus.CREATED,
				customCode: 'WGS0077',
				data: provider,
			});
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
				customCode: 'WGE0135',
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
	async findAll(
		@Query() getProvidersDto: GetProvidersDto,
		@Req() req,
		@Res() res
	) {
		try {
			const userInfo = req.user;
			const userFind = await this.userService.findOneByEmail(
				userInfo?.UserAttributes?.[0]?.Value
			);
			if (userFind?.type !== 'PLATFORM') {
				return res.status(HttpStatus.NOT_ACCEPTABLE).send({
					statusCode: HttpStatus.NOT_ACCEPTABLE,
					customCode: 'WGE0017',
				});
			}
			const userRoleId = userFind.roleId;
			const requiredMethod = req.method;
			const requestedModuleId = this.userService.getModuleIdFromPath(
				req.route.path
			);
			const role = await this.roleService.getRoleInfo(userRoleId);
			const permissionModule = role?.PlatformModules?.find(
				module => module[requestedModuleId]
			);
			const providers = await this.providerService.findAll(
				getProvidersDto,
				permissionModule,
				requestedModuleId,
				requiredMethod
			);
			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0135',
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
	async findOne(@Param('id') id: string, @Req() req) {
		try {
			const userInfo = req.user;
			const userFind = await this.userService.findOneByEmail(
				userInfo?.UserAttributes?.[0]?.Value
			);
			const userRoleId = userFind.roleId;
			const role = await this.roleService.getRoleInfo(userRoleId);
			const provider = await this.providerService.findOne(id, role, id);
			if (provider?.customCode) {
				return {
					customCode: provider?.customCode,
				};
			}
			if (!provider) {
				return {
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0040',
				};
			}
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0074',
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
		@Body() updateProviderDto: UpdateProviderDto,
		@Req() req
	) {
		try {
			const providerFind = await this.providerService.searchFindOne(id);
			if (!providerFind) {
				return {
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0040',
				};
			}
			const userInfo = req.user;
			const userFind = await this.userService.findOneByEmail(
				userInfo?.UserAttributes?.[0]?.Value
			);
			const userRoleId = userFind.roleId;
			const role = await this.roleService.getRoleInfo(userRoleId);
			const provider = await this.providerService.update(
				id,
				updateProviderDto,
				role,
				id
			);
			if (provider?.customCode) {
				return {
					customCode: provider?.customCode,
				};
			}
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGS0034',
				data: provider,
			};
		} catch (error) {
			console.log('error', error?.message);
			Sentry.captureException(error);
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0140',
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
		@Body() changeStatusProvider: ChangeStatusProviderDto,
		@Req() req
	) {
		try {
			const providerFind = await this.providerService.searchFindOne(id);
			if (!providerFind) {
				return {
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0040',
				};
			}
			const userInfo = req.user;
			const userFind = await this.userService.findOneByEmail(
				userInfo?.UserAttributes?.[0]?.Value
			);
			const userRoleId = userFind.roleId;
			const role = await this.roleService.getRoleInfo(userRoleId);
			const provider = await this.providerService.activeInactiveProvider(
				id,
				changeStatusProvider,
				role,
				id
			);
			if (provider?.customCode) {
				return {
					customCode: provider?.customCode,
				};
			}
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
				data: { provider: convertToCamelCase(provider) },
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0041',
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
				customCode: 'WGE0139',
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
	@ApiParam({
		name: 'id',
		required: false,
		description: 'Optional provider ID',
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
				customCode: 'WGE0139',
				data: { userProvider: convertToCamelCase(userProvider) },
			});
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					statusCode: HttpStatus.FORBIDDEN,
					customCode: 'WGE0040',
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Put('edit/users/:id?')
	@UsePipes(ValidationPipe)
	@ApiOperation({ summary: 'Upload service provider image' })
	@ApiParam({ name: 'id', description: 'ID of the provider', type: String })
	@ApiResponse({ status: 200, description: 'Provider updated successfully.' })
	@ApiResponse({ status: 500, description: 'Error updating provider.' })
	async uploadProviderUsers(
		@Body() updateUserDto: UpdateUserDto,
		@Req() req,
		@Param('id') id?: string
	) {
		try {
			const userRequest = req.user?.UserAttributes;

			const usersProvider = await this.providerService.updateProviderUsers(
				updateUserDto,
				userRequest,
				id
			);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0075',
				data: { users: convertToCamelCase(usersProvider) },
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0041',
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@UsePipes(ValidationPipe)
	@ApiOperation({
		summary: 'Create or update a new payment parameters for service providers',
	})
	@ApiParam({
		name: 'paymentParameterId',
		description: 'ID del paymentParamter',
		type: String,
	})
	@ApiBody({
		schema: {
			example: {
				name: 'Provider1_Paramter',
				description: 'Parameter for service provider 1',
				cost: 10,
				frequency: 'MINUTES',
				interval: 30,
				asset: 'USD',
				serviceProviderId: '8bf931ea-3710-420b-ae68-921f94bcd937',
			},
		},
	})
	@ApiResponse({
		status: 201,
		description: 'Payment Parameter created succefully',
	})
	@ApiResponse({
		status: 404,
		description: 'PaymentParameterId for service provider not found ',
	})
	@Post('payment-parameters/:paymentParameterId?')
	async createOrUpdatePaymentParameters(
		@Param('paymentParameterId') paymentParameterId: string | undefined,
		@Body()
		createProviderPaymentParameterDTO: CreateProviderPaymentParameterDTO,
		@Res() res
	) {
		try {
			const paymentParameter =
				await this.providerService.createOrUpdatePaymentParameter(
					paymentParameterId,
					createProviderPaymentParameterDTO
				);

			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0116',
				data: convertToCamelCase(paymentParameter),
			});
		} catch (error) {
			Sentry.captureException(error);

			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0115',
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@ApiOperation({
		summary: 'List payment parameters for a service providers',
	})
	@ApiParam({
		name: 'id',
		description: 'ID del service provider ',
		type: String,
	})
	@ApiResponse({
		status: 200,
		description: 'Lista de parametros de pago obtenida con éxito.',
	})
	@Get(':id/payment-parameters')
	async listPaymentParameters(
		@Param('id') id: string,
		@Query() getProviderPaymentParametersDTO: GetProviderPaymentParametersDTO
	) {
		try {
			const paymentParameters = await this.providerService.getPaymentParameters(
				id,
				getProviderPaymentParametersDTO
			);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0118',
				data: paymentParameters,
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					customCode: 'WGE0119',
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@ApiOperation({
		summary: 'List time intervals',
	})
	@ApiResponse({
		status: 200,
		description: 'Lista de intervalos de tiempo obtenida con éxito.',
	})
	@Get('list/time-intervals')
	async listTimeIntervals() {
		try {
			const timeIntervals = await this.providerService.getTimeIntervals();
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0120',
				data: timeIntervals,
			};
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					customCode: 'WGE0121',
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}
}
