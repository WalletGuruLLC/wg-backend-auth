export class CreateProviderDto {
	id: string;
	name: string;
	description: string;
	email: string;
	phone: string;
}

export class UpdateProviderDto {
	name?: string;
	description?: string;
	email?: string;
	phone?: string;
}
