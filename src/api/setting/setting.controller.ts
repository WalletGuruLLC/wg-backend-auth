import {
	ApiOkResponse,
	ApiTags,
	ApiQuery,
	ApiForbiddenResponse,
	ApiBearerAuth,
} from '@nestjs/swagger';
import {
	Body,
	Controller,
	Get,
	HttpException,
	HttpStatus,
	Param,
	Put,
	Query,
	Req,
	Res,
	UseGuards,
} from '@nestjs/common';
import { SettingService } from './setting.service';
import { CognitoAuthGuard } from '../user/guard/cognito-auth.guard';
import { UpdateSettingsDto } from './dto/update-settings.dto';
import { UserService } from '../user/service/user.service';

@Controller('api/v1/settings')
@ApiTags('settings')
@ApiBearerAuth('JWT')
export class SettingController {
	constructor(
		private readonly settingService: SettingService,
		private readonly userSevice: UserService
	) {}

	@Get()
	@ApiQuery({ name: 'belongs', required: false, type: String })
	@ApiOkResponse({
		description: 'Successfully returned settings',
	})
	async findAll(@Query('belongs') belongs?: string) {
		const settings = await this.settingService.findAll(belongs);
		return {
			statusCode: HttpStatus.OK,
			message: 'Successfully returned settings',
			data: settings,
		};
	}

	@UseGuards(CognitoAuthGuard)
	@Put('/:id')
	@ApiOkResponse({
		description: 'The record has been successfully updated.',
	})
	@ApiForbiddenResponse({ description: 'Forbidden.' })
	async update(
		@Param('id') id: string,
		@Body() updateSettings: UpdateSettingsDto,
		@Req() req,
		@Res() res
	) {
		try {
			const userInfo = req.user;
			const user = await this.userSevice.findOneByEmail(
				userInfo?.UserAttributes?.[0]?.Value
			);

			if (user?.type !== 'PLATFORM') {
				return res.status(HttpStatus.NOT_FOUND).send({
					statusCode: HttpStatus.NOT_FOUND,
					customCode: 'WGE0196',
				});
			}

			const resultAccess = await this.userSevice.validateAccess(
				req.token,
				req.route.path,
				req.method
			);

			if (resultAccess?.customCode) {
				return res.status(resultAccess?.statusCode).send(resultAccess);
			}

			if (!resultAccess.hasAccess) {
				return res.status(HttpStatus.UNAUTHORIZED).send({
					statusCode: HttpStatus.UNAUTHORIZED,
					customCode: 'WGE0038',
				});
			}

			const settings = await this.settingService.update(id, updateSettings);

			return res.status(HttpStatus.OK).send({
				statusCode: HttpStatus.OK,
				customCode: 'WGE0197',
				data: settings,
			});
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0016',
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}
}
