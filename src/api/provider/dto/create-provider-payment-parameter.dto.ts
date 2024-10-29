import {
	IsEnum,
	IsNotEmpty,
	IsNumber,
	IsOptional,
	IsPositive,
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
	@IsPositive()
	cost: number;

	@IsNumber()
	@IsNotEmpty()
	@IsPositive()
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
