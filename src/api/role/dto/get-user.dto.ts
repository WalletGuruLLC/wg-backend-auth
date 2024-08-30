import { IsBoolean, IsOptional, IsString } from 'class-validator';

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

	@IsOptional()
	@IsString()
	orderBy?: string;

	@IsOptional()
	@IsBoolean()
	ascending?: boolean;
}
