export class CreateProviderDto {
	id: string;
	name: string;
	description: string;
	email: string;
	phone: string;
	einNumber: string;
	country: string;
	city: string;
	zipCode: string;
	companyAddress: string;
	walletAddress: string;
	logo: string;
	contactInformation: string;
}
export class UpdateProviderDto {
	name?: string;
	description?: string;
	email?: string;
	phone?: string;
	einNumber?: string;
	country?: string;
	city?: string;
	zipCode?: string;
	companyAddress?: string;
	walletAddress?: string;
	logo?: string;
	contactInformation?: string;
	active?: boolean;
}

export class DeleteProviderDto {
	email?: string;
	active?: boolean;
}
