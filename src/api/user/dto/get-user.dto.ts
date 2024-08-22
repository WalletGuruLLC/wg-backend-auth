import { IsOptional, IsString } from 'class-validator';

export class GetUsersDto {
	@IsOptional()
	@IsString()
	type?: string;

	@IsOptional()
	@IsString()
	firstName?: string;

	@IsOptional()
	@IsString()
	lastName?: string;

	@IsOptional()
	@IsString()
	email?: string;

	@IsOptional()
	@IsString()
	id?: string;

	@IsOptional()
	@IsString()
	limit?: number;

	@IsOptional()
	@IsString()
	skip?: number;
}
