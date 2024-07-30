export class CreateUserDto {
	Id: string;
	Username: string;
	Email: string;
	PasswordHash: string;
	ServiceProvider: string;
	MfaEnabled: boolean;
	MfaType: string;
	Rol: string;
}
