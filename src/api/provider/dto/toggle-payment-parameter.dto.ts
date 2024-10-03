import { IsOptional, IsString } from 'class-validator';

export class TogglePaymentParameterDTO {
	@IsOptional()
	@IsString()
	serviceProviderId?: string;
}
