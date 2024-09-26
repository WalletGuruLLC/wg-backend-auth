import {
	ApiBearerAuth,
	ApiOkResponse,
	ApiTags,
	ApiQuery,
} from '@nestjs/swagger';
import {
	Controller,
	Get,
	HttpStatus,
	UseGuards,
	Query,
	Req,
} from '@nestjs/common';

import { ModuleService } from './module.service';
import { CognitoAuthGuard } from '../../api/user/guard/cognito-auth.guard';
import { UserService } from '../user/service/user.service';
import { parseStringToBoolean } from 'src/utils/helpers/parseStringToBoolean';

@Controller('api/v1/modules')
@ApiTags('modules')
@ApiBearerAuth('JWT')
export class ModuleController {
	constructor(
		private readonly moduleService: ModuleService,
		private readonly userService: UserService
	) {}

	@UseGuards(CognitoAuthGuard)
	@Get()
	@ApiQuery({ name: 'belongs', required: false, type: String })
	@ApiOkResponse({
		description: 'Successfully returned modules',
	})
	async findAll(
		@Req() req,
		@Query('belongs') belongs?: string,
		@Query('isProvider') isProvider?: boolean
	) {
		const userInfo = req.user;
		const user = await this.userService.findOneByEmail(
			userInfo?.UserAttributes?.[0]?.Value
		);

		let types = ['AL', 'WG'];
		if (user?.type == 'PROVIDER' || parseStringToBoolean(isProvider)) {
			types = ['AL', 'SP'];
		}

		const modules = await this.moduleService.findAll(belongs, types);
		return {
			statusCode: HttpStatus.OK,
			customCode: 'WGE0143',
			message: 'Successfully returned modules',
			data: modules,
		};
	}
}
