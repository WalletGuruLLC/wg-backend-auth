import { IsEnum, IsNumber, IsOptional, IsString } from 'class-validator';
import { Frequency } from './frequency.enum';
import { Asset } from './asset.enum';

export class CreateProviderPaymentParameterDTO {
	@IsString()
	@IsOptional()
	id?: string;

	@IsString()
	name: string;

	@IsString()
	description: string;

	@IsNumber()
	cost: number;

	@IsEnum(Frequency)
	frequency: Frequency;

	@IsNumber()
	interval: number;

	@IsEnum(Asset)
	asset: Asset;

	percent?: number;

	comision?: number;

	base?: number;

	@IsString()
	serviceProviderId: string;
}
