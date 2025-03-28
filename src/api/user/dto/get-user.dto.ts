import { IsBoolean, IsOptional, IsString } from 'class-validator';

export class GetUsersDto {
	@IsOptional()
	@IsString()
	type?: string;

	@IsOptional()
	@IsString()
	search?: string;

	@IsOptional()
	@IsString()
	firstName?: string;

	@IsOptional()
	@IsString()
	lastName?: string;

	@IsOptional()
	@IsString()
	serviceProviderId?: string;

	@IsOptional()
	@IsString()
	email?: string;

	@IsOptional()
	@IsString()
	id?: string;

	@IsOptional()
	@IsString()
	items?: number;

	@IsOptional()
	@IsString()
	page?: number;

	@IsOptional()
	@IsString()
	orderBy?: string;

	@IsOptional()
	@IsBoolean()
	ascending?: boolean;

	@IsOptional()
	@IsString()
	state?: number;

	@IsOptional()
	@IsString()
	wallet?: string;
}
