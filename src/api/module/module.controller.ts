import { ApiBearerAuth, ApiOkResponse, ApiTags } from '@nestjs/swagger';
import { Controller, Get, HttpStatus, UseGuards, Req } from '@nestjs/common';

import { ModuleService } from './module.service';
import { CognitoAuthGuard } from '../../api/user/guard/cognito-auth.guard';

@Controller('api/v1/modules')
@ApiTags('modules')
@ApiBearerAuth('JWT')
export class ModuleController {
	constructor(private readonly moduleService: ModuleService) {}

	@UseGuards(CognitoAuthGuard)
	@Get()
	@ApiOkResponse({
		description: 'Successfully returned modules',
	})
	async findAll(@Req() req) {
		const modules = await this.moduleService.findAll(req.user);
		return {
			statusCode: HttpStatus.OK,
			message: 'Successfully returned modules',
			data: modules,
		};
	}
}
