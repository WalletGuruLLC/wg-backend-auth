import { IsNotEmpty, IsString } from 'class-validator';

export class RefreshTokeenDTO {
	@IsString()
	@IsNotEmpty()
	token: string;

	@IsString()
	@IsNotEmpty()
	email: string;
}
