import {
	IsEnum,
	IsNotEmpty,
	IsNumber,
	IsOptional,
	IsPositive,
	IsString,
} from 'class-validator';

export class UpdatePaymentParameterDTO {
	@IsString()
	@IsNotEmpty()
	name: string;

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
}
