import {
	Controller,
	Get,
	HttpException,
	HttpStatus,
	Post,
	Res,
	UseGuards,
} from '@nestjs/common';
import {
	ApiBearerAuth,
	ApiCreatedResponse,
	ApiForbiddenResponse,
	ApiTags,
} from '@nestjs/swagger';
import { errorCodes } from '../../../utils/constants';
import * as Sentry from '@sentry/nestjs';
import { HealthService } from '../service/health.service';
import { HealthResonseDto } from '../dto/health-response.dto';
import { CognitoAuthGuard } from '../../user/guard/cognito-auth.guard';
import { UserService } from '../../user/service/user.service';

@ApiTags('health-check')
@Controller('api/v1/health-check')
@ApiBearerAuth('JWT')
export class HealthController {
	constructor(private readonly healthService: HealthService) {}

	// @UseGuards(CognitoAuthGuard)
	@Post('/')
	@ApiCreatedResponse({
		description: 'verify health check',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async healthCheck(@Res() res) {
		try {
			return res.status(HttpStatus.OK).json({
				status: 'ok',
				message: 'Health check successful',
			});
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0016',
					customMessage: errorCodes.WGE0016?.description,
					customMessageEs: errorCodes.WGE0016?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@UseGuards(CognitoAuthGuard)
	@Get('/uptime')
	@ApiCreatedResponse({
		description: 'retrieve uptime information',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async getInfoUptime(@Res() res) {
		try {
			const token = await this.healthService.getTokenUptime();
			const data = await this.healthService.getDataUptime(token);
			const resuls = [];
			for (const item of data.monitors) {
				resuls.push({
					id: item.id,
					name: item.name,
					beats: await this.healthService.getBeatUptime(item.id, 1, token),
				});
			}
			return res.status(HttpStatus.OK).json({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0188',
				data: {
					monitors: resuls,
				},
			});
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0016',
					customMessage: errorCodes.WGE0016?.description,
					customMessageEs: errorCodes.WGE0016?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}
}
