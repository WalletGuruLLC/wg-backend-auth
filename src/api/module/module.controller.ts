import { ApiOkResponse, ApiTags } from '@nestjs/swagger';
import { Controller, Get, HttpStatus } from '@nestjs/common';
import { ModuleService } from './module.service';

@Controller('api/v1/modules')
@ApiTags('modules')
export class ModuleController {
	constructor(private readonly moduleService: ModuleService) {}

	@Get()
	@ApiOkResponse({
		description: 'Successfully returned modules',
	})
	async findAll() {
		const modules = await this.moduleService.findAll();
		return {
			statusCode: HttpStatus.OK,
			message: 'Successfully returned modules',
			data: modules,
		};
	}
}
