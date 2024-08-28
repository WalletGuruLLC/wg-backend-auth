import { IsOptional, IsString } from 'class-validator';

export class GetProvidersDto {
	@IsOptional()
	@IsString()
	search?: string;
}
