import {
	Body,
	Controller,
	HttpStatus,
	Param,
	Post,
	UseGuards,
	Res,
	Req,
	Get,
} from '@nestjs/common';
import {
	ApiBearerAuth,
	ApiBody,
	ApiOperation,
	ApiParam,
	ApiResponse,
	ApiTags,
} from '@nestjs/swagger';

import { CognitoAuthGuard } from '../../user/guard/cognito-auth.guard';
import { UserService } from 'src/api/user/service/user.service';
import { MuteNotificationsDto } from '../dto/mute-notifications.dto';
import { NotificationsService } from '../service/notifications.service';

@ApiTags('notifications')
@Controller('api/v1/notifications')
@ApiBearerAuth('JWT')
export class NotificationsController {
	constructor(
		private readonly notificationsService: NotificationsService,
		private readonly userService: UserService
	) {}

	@UseGuards(CognitoAuthGuard)
	@ApiOperation({
		summary: 'Check if notifications are active for a user',
	})
	@ApiParam({
		name: 'userId',
		description: 'ID of the user',
		type: String,
	})
	@ApiResponse({
		status: 200,
		description: 'Notification status retrieved successfully.',
	})
	@ApiResponse({ status: 404, description: 'User not found' })
	@Get('/status/:userId')
	async areNotificationsActive(@Param('userId') userId: string, @Res() res) {
		try {
			const user = await this.userService.findOneById(userId);
			if (!user) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
					message: 'User not found',
				});
			}

			const isActive = await this.notificationsService.areNotificationsActive(
				userId
			);
			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0188',
				data: { notificationsActive: isActive },
			});
		} catch (error) {
			return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send({
				statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
				customCode: 'WGE0189',
				message: 'Internal server error',
			});
		}
	}

	@UseGuards(CognitoAuthGuard)
	@ApiOperation({
		summary: 'Activate or deactivate all notifications for a user',
	})
	@ApiParam({
		name: 'userId',
		description: 'ID of the user whose notifications will be updated',
		type: String,
	})
	@ApiBody({
		schema: { example: { notificationsActive: true } },
	})
	@ApiResponse({
		status: 201,
		description: 'Notifications status updated successfully.',
	})
	@ApiResponse({ status: 404, description: 'User not found' })
	@Post('/toggle/:userId')
	async toggleNotifications(
		@Param('userId') userId: string,
		@Body() body: { notificationsActive: boolean },
		@Res() res,
		@Req() req
	) {
		try {
			const userInfo = req.user;
			const userFind = await this.userService.findOneByEmail(
				userInfo?.UserAttributes?.[0]?.Value
			);

			const user = await this.userService.findOneById(userId);
			if (!user) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
				});
			}

			if (userFind?.id !== userId) {
				return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send({
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0038',
				});
			}

			if (userFind?.type !== 'WALLET') {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0038',
				});
			}

			if (typeof body.notificationsActive !== 'boolean') {
				return res.status(HttpStatus.BAD_REQUEST).send({
					statusCode: HttpStatus.BAD_REQUEST,
					customCode: 'WGE0190',
					message: 'Invalid value for notificationsActive',
				});
			}

			await this.notificationsService.toggleNotifications(
				userId,
				body.notificationsActive
			);

			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0191',
				message: 'Notifications status updated successfully',
			});
		} catch (error) {
			return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send({
				statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
				customCode: 'WGE0192',
				message: 'Internal server error',
			});
		}
	}

	@UseGuards(CognitoAuthGuard)
	@ApiOperation({
		summary: 'Mute notifications for a user',
	})
	@ApiParam({
		name: 'userId',
		description: 'ID of the user whose notifications will be muted',
		type: String,
	})
	@ApiBody({
		type: MuteNotificationsDto,
		description: 'Mute notifications for a certain duration',
		examples: {
			'30 minutes': { value: { duration: '30m' } },
			'1 hour': { value: { duration: '1h' } },
			Never: { value: { duration: 'never' } },
		},
	})
	@ApiResponse({
		status: 201,
		description: 'Notifications muted successfully.',
	})
	@ApiResponse({ status: 400, description: 'Invalid mute duration' })
	@ApiResponse({ status: 404, description: 'User not found' })
	@Post('/mute/:userId')
	async muteNotifications(
		@Param('userId') userId: string,
		@Body() muteDto: MuteNotificationsDto,
		@Res() res,
		@Req() req
	) {
		try {
			const userInfo = req.user;
			const userFind = await this.userService.findOneByEmail(
				userInfo?.UserAttributes?.[0]?.Value
			);

			const user = await this.userService.findOneById(userId);
			if (!user) {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0002',
				});
			}

			if (userFind?.id !== userId) {
				return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send({
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0038',
				});
			}

			if (userFind?.type !== 'WALLET') {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0038',
				});
			}

			const validDurations = ['30m', '1h', 'never'];
			if (!validDurations.includes(muteDto.duration)) {
				return res.status(HttpStatus.BAD_REQUEST).send({
					statusCode: HttpStatus.BAD_REQUEST,
					customCode: 'WGE0193',
					message: 'Invalid mute duration',
				});
			}

			await this.notificationsService.muteNotifications(
				userId,
				muteDto.duration
			);

			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0194',
				message: 'Notifications muted successfully',
			});
		} catch (error) {
			return res.status(HttpStatus.INTERNAL_SERVER_ERROR).send({
				statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
				customCode: 'WGE0195',
				message: 'Internal server error',
			});
		}
	}
}
