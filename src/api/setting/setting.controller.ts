import { ApiOkResponse, ApiTags, ApiQuery } from '@nestjs/swagger';
import { Controller, Get, HttpStatus, Query } from '@nestjs/common';
import { SettingService } from './setting.service';

@Controller('api/v1/settings')
@ApiTags('settings')
export class SettingController {
	constructor(private readonly settingService: SettingService) {}

	@Get()
	@ApiQuery({ name: 'belong', required: false, type: String })
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
}
