export class CreateRoleDto {
	id: string;
	name: string;
	description: string;
}

export class UpdateRoleDto {
	name?: string;
	description?: string;
}
