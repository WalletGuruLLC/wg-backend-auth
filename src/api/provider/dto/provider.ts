import { IsOptional, IsString } from 'class-validator';

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
	asset: string;
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
	asset: string;
	contactInformation?: string;
	active?: boolean;
	ImageUrl?: string;
}

export class ChangeStatusProviderDto {
	email?: string;
	active?: boolean;
}

export class CreateSocketDto {
	@IsOptional()
	@IsString()
	publicKey?: string;

	@IsOptional()
	@IsString()
	secretKey?: string;

	@IsOptional()
	@IsString()
	serviceProviderId?: string;
}
