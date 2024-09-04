import {
	ApiBearerAuth,
	ApiOkResponse,
	ApiTags,
	ApiQuery,
} from '@nestjs/swagger';
import { Controller, Get, HttpStatus, UseGuards, Query } from '@nestjs/common';

import { ModuleService } from './module.service';
import { CognitoAuthGuard } from '../../api/user/guard/cognito-auth.guard';

@Controller('api/v1/modules')
@ApiTags('modules')
@ApiBearerAuth('JWT')
export class ModuleController {
	constructor(private readonly moduleService: ModuleService) {}

	@UseGuards(CognitoAuthGuard)
	@Get()
	@ApiQuery({ name: 'belongs', required: false, type: String })
	@ApiOkResponse({
		description: 'Successfully returned modules',
	})
	async findAll(@Query('belongs') belongs?: string) {
		const modules = await this.moduleService.findAll(belongs);
		return {
			statusCode: HttpStatus.OK,
			message: 'Successfully returned modules',
			data: modules,
		};
	}
}
