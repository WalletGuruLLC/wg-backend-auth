import { IsOptional, IsString } from 'class-validator';

export class GetRolesDto {
	@IsOptional()
	@IsString()
	search?: string;

	@IsOptional()
	@IsString()
	providerId?: string;

	@IsOptional()
	@IsString()
	items?: string;

	@IsOptional()
	@IsString()
	page?: string;
}
