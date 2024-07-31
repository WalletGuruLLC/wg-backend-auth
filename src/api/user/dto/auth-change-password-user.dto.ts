import { IsEmail, Matches } from 'class-validator';

export class AuthChangePasswordUserDto {
	@IsEmail()
	email: string;

	@Matches(
		/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$&+,:;=?@#|'<>.^*()%!-])[A-Za-z\d@$&+,:;=?@#|'<>.^*()%!-]{8,}$/,
		{ message: 'invalid password' }
	)
	currentPassword: string;

	@Matches(
		/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$&+,:;=?@#|'<>.^*()%!-])[A-Za-z\d@$&+,:;=?@#|'<>.^*()%!-]{8,}$/,
		{ message: 'invalid password' }
	)
	newPassword: string;
}
