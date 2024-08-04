import { Injectable } from '@nestjs/common';
import { ProviderModel, ProviderDocument } from '../entities/provider.entity';
import { CreateProviderDto, UpdateProviderDto } from '../dto/provider';

@Injectable()
export class ProviderService {
	async create(
		createProviderDto: CreateProviderDto
	): Promise<ProviderDocument> {
		const provider = new ProviderModel(createProviderDto);
		return provider.save() as Promise<ProviderDocument>;
	}

	async findAll(): Promise<ProviderDocument[]> {
		const scanResults = await ProviderModel.scan().exec();
		return scanResults as unknown as ProviderDocument[];
	}

	async findOne(id: string): Promise<ProviderDocument> {
		return ProviderModel.get(id) as Promise<ProviderDocument>;
	}

	async update(
		id: string,
		updateProviderDto: UpdateProviderDto
	): Promise<ProviderDocument> {
		return ProviderModel.update(
			{ id },
			updateProviderDto
		) as Promise<ProviderDocument>;
	}

	async remove(id: string): Promise<void> {
		await ProviderModel.delete(id);
	}
}
