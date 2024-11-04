import {
	Body,
	Controller,
	Get,
	HttpException,
	HttpStatus,
	Param,
	Patch,
	Post,
	Query,
	Res,
	UseGuards,
	UsePipes,
	ValidationPipe,
	Req,
	Put,
} from '@nestjs/common';
import { ProviderService } from '../service/provider.service';
import * as Sentry from '@sentry/nestjs';
import {
	ApiBearerAuth,
	ApiBody,
	ApiOperation,
	ApiParam,
	ApiResponse,
	ApiTags,
} from '@nestjs/swagger';
import { CognitoAuthGuard } from '../../user/guard/cognito-auth.guard';
import { convertToCamelCase } from '../../../utils/helpers/convertCamelCase';
import { CreateProviderPaymentParameterDTO } from '../dto/create-provider-payment-parameter.dto';
import { GetPaymentsParametersPaginated } from '../dto/get-payment-parameters-paginated';
import { TogglePaymentParameterDTO } from '../dto/toggle-payment-parameter.dto';
import { UserService } from 'src/api/user/service/user.service';
import { UpdatePaymentParameterDTO } from '../dto/update-provider-payment-parameter.dto';

@ApiTags('payment')
@ApiBearerAuth('JWT')
@Controller('api/v1/payments')
export class PaymentController {
	constructor(
		private readonly providerService: ProviderService,
		private readonly userService: UserService
	) {}

	@UseGuards(CognitoAuthGuard)
	@UsePipes(ValidationPipe)
	@ApiOperation({
		summary: 'Create a new payment parameters for service providers',
	})
	@ApiBody({
		schema: {
			example: {
				name: 'Provider1_Paramter',
				cost: 10,
				frequency: 30,
				timeIntervalId: '5894d088-0cc6-4aea-9df5-ba348c9d364d',
				serviceProviderId: '8bf931ea-3710-420b-ae68-921f94bcd937',
			},
		},
	})
	@ApiResponse({
		status: 201,
		description: 'Payment Parameter created succefully',
	})
	@Post('create/payment-parameters')
	async createPaymentParameters(
		@Body()
		createProviderPaymentParameterDTO: CreateProviderPaymentParameterDTO,
		@Res() res,
		@Req() req
	) {
		const userRequest = req.user?.UserAttributes;
		const token = req?.token.toString().split(' ')?.[1];
		try {
			const providerId = await this.providerService.getProviderId(
				createProviderPaymentParameterDTO?.serviceProviderId,
				userRequest
			);

			if (!providerId) {
				return res.status(HttpStatus.BAD_REQUEST).send({
					statusCode: HttpStatus.BAD_REQUEST,
					customCode: 'WGE0147',
				});
			}

			const provider = await this.providerService.searchFindOneId(providerId);

			if (!provider) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0040',
				});
			}

			const timeInterval = await this.providerService.getTimeIntervalById(
				createProviderPaymentParameterDTO.timeIntervalId
			);

			if (!timeInterval) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0115',
				});
			}

			const paymentParameter =
				await this.providerService.createPaymentParameter(
					createProviderPaymentParameterDTO,
					provider,
					timeInterval,
					token
				);

			if (paymentParameter?.statusCode) {
				return res.status(paymentParameter?.statusCode).send({
					statusCode: paymentParameter?.statusCode,
					customCode: paymentParameter?.customCode,
				});
			}

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
	@UsePipes(ValidationPipe)
	@ApiOperation({
		summary: 'Update a payment parameter for service providers',
	})
	@ApiBody({
		schema: {
			example: {
				name: 'Provider1_Paramter',
				cost: 10,
				frequency: 30,
				timeIntervalId: '5894d088-0cc6-4aea-9df5-ba348c9d364d',
				serviceProviderId: '8bf931ea-3710-420b-ae68-921f94bcd937',
			},
		},
	})
	@ApiResponse({
		status: 201,
		description: 'Payment Parameter updated succefully',
	})
	@ApiResponse({
		status: 404,
		description: 'PaymentParameterId for service provider not found ',
	})
	@Put('payment-parameters/:paymentParameterId')
	async updatePaymentParameter(
		@Body()
		updatePaymentParameter: UpdatePaymentParameterDTO,
		@Res() res,
		@Req() req,
		@Param('paymentParameterId') paymentParameterId: string
	) {
		const userRequest = req.user?.UserAttributes;

		try {
			const providerId = await this.providerService.getProviderId(
				updatePaymentParameter.serviceProviderId,
				userRequest
			);

			if (!providerId) {
				return res.status(HttpStatus.BAD_REQUEST).send({
					statusCode: HttpStatus.BAD_REQUEST,
					customCode: 'WGE0147',
				});
			}

			const provider = await this.providerService.searchFindOneId(providerId);

			if (!provider) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0040',
				});
			}

			const existingPaymentParameter =
				await this.providerService.getPaymentParameters(
					paymentParameterId,
					providerId
				);

			if (!existingPaymentParameter) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0119',
				});
			}

			const timeInterval = await this.providerService.getTimeIntervalById(
				updatePaymentParameter.timeIntervalId
			);

			if (!timeInterval) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0115',
				});
			}

			const updatedPaymentParameter =
				await this.providerService.updatePaymentParameter(
					paymentParameterId,
					updatePaymentParameter
				);

			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0116',
				data: convertToCamelCase(updatedPaymentParameter),
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
	@ApiResponse({
		status: 200,
		description: 'Lista de parametros de pago obtenida con éxito.',
	})
	@Get('list/payment-parameters')
	async listPaymentParameters(
		@Req() req,
		@Res() res,
		@Query() getPaymentsParametersPaginated: GetPaymentsParametersPaginated
	) {
		try {
			const userRequest = req.user?.UserAttributes;
			const providerId = await this.providerService.getProviderId(
				getPaymentsParametersPaginated?.serviceProviderId,
				userRequest
			);
			if (!providerId) {
				return res.status(HttpStatus.BAD_REQUEST).send({
					statusCode: HttpStatus.BAD_REQUEST,
					customCode: 'WGE0147',
				});
			}

			const provider = await this.providerService.searchFindOneId(providerId);

			if (!provider) {
				return res.status(HttpStatus.BAD_REQUEST).send({
					statusCode: HttpStatus.BAD_REQUEST,
					customCode: 'WGE0147',
				});
			}

			const paymentParameters =
				await this.providerService.getPaymentsParametersPaginated({
					serviceProviderId: providerId,
					...getPaymentsParametersPaginated,
				});

			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0118',
				data: paymentParameters,
			});
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
	async listTimeIntervals(@Req() req, @Res() res) {
		try {
			const userInfo = req.user;
			const userFind = await this.userService.findOneByEmail(
				userInfo?.UserAttributes?.[0]?.Value
			);
			if (!userFind) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
				});
			}

			if (['WALLET'].includes(userFind?.type)) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0038',
				});
			}

			const timeIntervals = await this.providerService.getTimeIntervals();
			
			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0128',
				data: timeIntervals,
			});
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					customCode: 'WGE0129',
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Patch('payment-parameters/:paymentParameterId/toggle')
	@ApiOperation({ summary: 'Toggle the active status of a payment parameter' })
	@ApiBody({
		required: false,
		schema: {
			example: {
				serviceProviderId: '8bf931ea-3710-420b-ae68-921f94bcd937',
			},
		},
	})
	@ApiParam({
		name: 'paymentParameterId',
		description: 'ID of the payment parameter',
		type: String,
	})
	@ApiResponse({
		status: 200,
		description: 'Payment parameter status toggled successfully.',
	})
	@ApiResponse({
		status: 404,
		description: 'Payment parameter not found.',
	})
	async paymentParameterToggle(
		@Param('paymentParameterId') paymentParameterId: string,
		@Req() req,
		@Body()
		togglePaymentParameterDTO: TogglePaymentParameterDTO,
		@Res() res
	) {
		try {
			const userRequest = req.user?.UserAttributes;

			const providerId = await this.providerService.getProviderId(
				togglePaymentParameterDTO?.serviceProviderId,
				userRequest
			);

			if (!providerId) {
				return res.status(HttpStatus.BAD_REQUEST).send({
					statusCode: HttpStatus.BAD_REQUEST,
					customCode: 'WGE0147',
				});
			}

			const provider = await this.providerService.searchFindOneId(providerId);

			if (!provider) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0040',
				});
			}

			const paymentParameter =
				await this.providerService.togglePaymentParameter(
					togglePaymentParameterDTO.serviceProviderId,
					paymentParameterId
				);

			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0160',
				data: paymentParameter,
			});
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0161',
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}
}
