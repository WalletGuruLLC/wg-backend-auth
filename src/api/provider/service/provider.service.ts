import * as dynamoose from 'dynamoose';
import { Model } from 'dynamoose/dist/Model';
import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import * as Sentry from '@sentry/nestjs';
import { errorCodes } from '../../../utils/constants';
import { Provider } from '../entities/provider.entity';
import { ProviderSchema } from '../entities/provider.schema';
import { CreateProviderDto, UpdateProviderDto } from '../dto/provider';
import { convertToCamelCase } from '../../../utils/helpers/convertCamelCase';

@Injectable()
export class ProviderService {
	private readonly dbInstance: Model<Provider>;

	constructor() {
		const tableName = 'Providers';
		this.dbInstance = dynamoose.model<Provider>(tableName, ProviderSchema, {
			create: false,
			waitForActive: false,
		});
	}

	async create(createProviderDto: CreateProviderDto): Promise<Provider> {
		const provider = {
			Name: createProviderDto.name,
			Description: createProviderDto.description,
			Email: createProviderDto.email,
			Phone: createProviderDto.phone,
		};
		return this.dbInstance.create(provider);
	}

	async findAll(search = '') {
		const scanResults = await this.dbInstance.scan().exec();

		let providers = scanResults as unknown as Provider[];

		if (search) {
			const regex = new RegExp(search, 'i');
			providers = providers.filter(
				provider => regex.test(provider.Email) || regex.test(provider.Name)
			);
		}

		return providers;
	}

	async findOne(id: string) {
		const provider = await this.dbInstance.get(id);
		if (!provider) {
			throw new HttpException(
				{
					customCode: 'WGE0040',
					...errorCodes.WGE0040,
				},
				HttpStatus.NOT_FOUND
			);
		}
		return provider;
	}

	async update(id: string, updateProviderDto: UpdateProviderDto) {
		try {
			return convertToCamelCase(
				await this.dbInstance.update({
					Id: id,
					Email: updateProviderDto.email,
					Description: updateProviderDto.description,
					Name: updateProviderDto.name,
				})
			);
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error updating user: ${error.message}`);
		}
	}

	async remove(id: string): Promise<void> {
		try {
			await this.dbInstance.delete(id);
		} catch (error) {
			Sentry.captureException(error);
			throw new Error(`Error updating user: ${error.message}`);
		}
	}
}
