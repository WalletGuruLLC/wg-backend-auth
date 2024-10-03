import { IsEnum, IsNumber, IsOptional, IsString } from 'class-validator';
import { Interval } from './interval.enum';
import { Asset } from './asset.enum';

export class CreateProviderPaymentParameterDTO {
	@IsString()
	@IsOptional()
	id?: string;

	@IsString()
	name: string;

	@IsString()
	@IsOptional()
	description?: string;

	@IsNumber()
	cost: number;

	@IsNumber()
	frequency: number;

	@IsString()
	timeIntervalId: string;

	@IsEnum(Asset)
	asset: Asset;

	@IsString()
	serviceProviderId: string;

	@IsString()
	@IsOptional()
	paymentParameterId?: string;
}
