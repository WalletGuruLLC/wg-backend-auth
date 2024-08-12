import { IsEmail, IsNotEmpty } from 'class-validator';

export class CreateOtpRequestDto {
	@IsEmail()
	@IsNotEmpty()
	email: string;
}
