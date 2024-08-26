import {
	Body,
	Controller,
	Delete,
	Get,
	HttpException,
	HttpStatus,
	Param,
	Patch,
	Post,
	UsePipes,
	ValidationPipe,
} from '@nestjs/common';
import { ProviderService } from '../service/provider.service';
import { CreateProviderDto, UpdateProviderDto } from '../dto/provider';

@Controller('api/v1/providers')
export class ProviderController {
	constructor(private readonly providerService: ProviderService) {}

	@Post()
	@UsePipes(ValidationPipe)
	async create(@Body() createProviderDto: CreateProviderDto) {
		try {
			const provider = await this.providerService.create(createProviderDto);
			return {
				statusCode: HttpStatus.CREATED,
				message: 'Provider created successfully',
				data: provider,
			};
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					message: `Error creating provider: ${error.message}`,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@Get()
	async findAll() {
		try {
			const providers = await this.providerService.findAll();
			return {
				statusCode: HttpStatus.OK,
				message: 'Providers retrieved successfully',
				data: providers,
			};
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					message: `Error retrieving providers: ${error.message}`,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@Get(':id')
	async findOne(@Param('id') id: string) {
		try {
			const provider = await this.providerService.findOne(id);
			if (!provider) {
				throw new HttpException('Provider not found', HttpStatus.NOT_FOUND);
			}
			return {
				statusCode: HttpStatus.OK,
				message: 'Provider found',
				data: provider,
			};
		} catch (error) {
			if (error.status === HttpStatus.NOT_FOUND) {
				throw error; // Re-throw 404 errors as they are
			}
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					message: `Error retrieving provider: ${error.message}`,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@Patch(':id')
	@UsePipes(ValidationPipe)
	async update(
		@Param('id') id: string,
		@Body() updateProviderDto: UpdateProviderDto
	) {
		try {
			const provider = {}; //await this.providerService.update(id, updateProviderDto);
			return {
				statusCode: HttpStatus.OK,
				message: 'Provider updated successfully',
				data: provider,
			};
		} catch (error) {
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					message: `Error updating provider: ${error.message}`,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
	}

	@Delete(':id')
	async remove(@Param('id') id: string) {
		try {
			await this.providerService.remove(id);
			return {
				statusCode: HttpStatus.OK,
				message: 'Provider deleted successfully',
			};
		} catch (error) {
			if (error.message === 'Provider not found in database') {
				throw new HttpException(
					{
						statusCode: HttpStatus.NOT_FOUND,
						message: error.message,
					},
					HttpStatus.NOT_FOUND
				);
			} else {
				throw new HttpException(
					{
						statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
						message: `Error deleting provider: ${error.message}`,
					},
					HttpStatus.INTERNAL_SERVER_ERROR
				);
			}
		}
	}
}
