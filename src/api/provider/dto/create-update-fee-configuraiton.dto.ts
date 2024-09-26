import { IsNumber, IsString } from 'class-validator';

export class CreateUpdateFeeConfigurationDTO {
	@IsNumber()
	percent: number;

	@IsNumber()
	comission: number;

	@IsNumber()
	base: number;

	@IsString()
	serviceProviderId: string;
}
