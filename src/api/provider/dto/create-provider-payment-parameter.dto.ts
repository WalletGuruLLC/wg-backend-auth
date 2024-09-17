import { IsNumber, IsOptional, IsString } from 'class-validator';
import { Frequency } from './frequency.enum';

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

	@IsString()
	frequency: Frequency;

	@IsNumber()
	interval: number;

	@IsString()
	asset: string;

	percent?: number;

	comision?: number;

	base?: number;

	@IsString()
	serviceProviderId: string;
}
