export class CreateRoleDto {
	id: string;
	name: string;
	description: string;
	belong: string;
	providerId?: string;
}

export class UpdateRoleDto {
	name?: string;
	description?: string;
}
