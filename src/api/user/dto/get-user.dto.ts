import { IsOptional, IsString } from 'class-validator';

export class GetUsersDto {
	@IsOptional()
	@IsString()
	type?: string;
}
