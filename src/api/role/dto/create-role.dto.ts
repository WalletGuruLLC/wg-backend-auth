import { IsString, Length, Matches, IsBoolean, IsIn } from 'class-validator';

export class CreateRoleDto {
	@IsString()
	@Length(5, 5)
	@Matches(/^[0-9A-Z]+$/)
	id: string;

	@IsString()
	@Length(1, 20)
	@Matches(/^[a-zA-Z\s´-_]+$/)
	name: string;

	@IsString()
	@Length(1, 50)
	@Matches(/^[a-zA-Z\s´-_]+$/)
	description: string;

	@IsString()
	@IsIn(['PLATFORM', 'PROVIDER'])
	belong: string;

	@IsString()
	@Length(6, 6)
	@Matches(/^[0-9A-Z]+$/)
	providerId: string;
}
