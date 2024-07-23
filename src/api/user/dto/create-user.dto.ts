export class CreateUserDto {
	Id: number;
	Username: string;
	Email: string;
	PasswordHash: string;
	MfaEnabled: boolean;
	MfaType: string;
	Rol: string;
}
