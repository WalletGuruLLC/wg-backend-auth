export class CreateUserDto {
	Id: string;
	Username: string;
	Email: string;
	PasswordHash: string;
	MfaEnabled: boolean;
	MfaType: string;
	Rol: string;
}
