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

@ApiTags('payment')
@ApiBearerAuth('JWT')
@Controller('api/v1/payments')
export class PaymentController {
	constructor(private readonly providerService: ProviderService) {}

	@UseGuards(CognitoAuthGuard)
	@UsePipes(ValidationPipe)
	@ApiOperation({
		summary: 'Create or update a new payment parameters for service providers',
	})
	@ApiBody({
		schema: {
			example: {
				name: 'Provider1_Paramter',
				cost: 10,
				frequency: 30,
				timeIntervalId: '5894d088-0cc6-4aea-9df5-ba348c9d364d',
				serviceProviderId: '8bf931ea-3710-420b-ae68-921f94bcd937',
				paymentParameterId: '8bf931ea-3710-420b-ae68-921f94bcd937',
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
	@Post('create/payment-parameters')
	async createOrUpdatePaymentParameters(
		@Body()
		createProviderPaymentParameterDTO: CreateProviderPaymentParameterDTO,
		@Res() res,
		@Req() req
	) {
		const userRequest = req.user?.UserAttributes;
		const token = req?.token.toString().split(' ')?.[1];
		try {
			let existingPaymentParameter;

			if (createProviderPaymentParameterDTO.paymentParameterId) {
				existingPaymentParameter =
					await this.providerService.getPaymentParameters(
						createProviderPaymentParameterDTO.paymentParameterId
					);

				if (
					createProviderPaymentParameterDTO.paymentParameterId &&
					!existingPaymentParameter
				) {
					return res.status(HttpStatus.NOT_FOUND).send({
						statusCode: HttpStatus.NOT_FOUND,
						customCode: 'WGE0119',
					});
				}
			}

			const providerId = await this.providerService.getProviderId(
				createProviderPaymentParameterDTO?.serviceProviderId,
				userRequest
			);

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
				await this.providerService.createOrUpdatePaymentParameter(
					createProviderPaymentParameterDTO,
					provider,
					existingPaymentParameter,
					timeInterval,
					token
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
			let providerId;
			if (userRequest) {
				providerId = await this.providerService.getProviderId(
					getPaymentsParametersPaginated?.serviceProviderId,
					userRequest
				);
			} else {
				providerId = getPaymentsParametersPaginated?.serviceProviderId;
				if (!providerId) {
					return res.status(HttpStatus.BAD_REQUEST).send({
						statusCode: HttpStatus.BAD_REQUEST,
						customCode: 'WGE0147',
					});
				}
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
	async listTimeIntervals() {
		try {
			const timeIntervals = await this.providerService.getTimeIntervals();
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0128',
				data: timeIntervals,
			};
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
		togglePaymentParameterDTO: TogglePaymentParameterDTO
	) {
		try {
			const userRequest = req.user?.UserAttributes;
			const paymentParameter =
				await this.providerService.togglePaymentParameter(
					togglePaymentParameterDTO.serviceProviderId,
					paymentParameterId,
					userRequest
				);
			return {
				statusCode: HttpStatus.OK,
				customCode: 'WGE0160',
				data: paymentParameter,
			};
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
