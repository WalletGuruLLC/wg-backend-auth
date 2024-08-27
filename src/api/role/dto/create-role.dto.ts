import { IsString, Length, Matches } from 'class-validator';

export class CreateRoleDto {
	@IsString()
	@Length(1, 20)
	@Matches(/^[\p{L}\s´\-_]+$/u)
	name: string;

	@IsString()
	@Length(0, 50)
	@Matches(/^[\p{L}\s´\-_]+$/u)
	description: string;

	@IsString()
	providerId? = 'EMPTY';
}
