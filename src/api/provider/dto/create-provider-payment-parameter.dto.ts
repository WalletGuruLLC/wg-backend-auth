import {
	IsEnum,
	IsNotEmpty,
	IsNumber,
	IsOptional,
	IsString,
} from 'class-validator';

export class CreateProviderPaymentParameterDTO {
	@IsString()
	@IsOptional()
	id?: string;

	@IsString()
	@IsNotEmpty()
	name: string;

	@IsString()
	@IsOptional()
	description?: string;

	@IsNumber()
	@IsNotEmpty()
	cost: number;

	@IsNumber()
	@IsNotEmpty()
	frequency: number;

	@IsString()
	@IsNotEmpty()
	timeIntervalId: string;

	@IsString()
	@IsOptional()
	serviceProviderId?: string;

	@IsString()
	@IsOptional()
	paymentParameterId?: string;
}
