export enum MfaTypeUser {
	SMS = 'SMS',
	TOTP = 'TOTP',
}

export enum StateUser {
	CREATE = 0,
	VERIFY = 1,
	KYC = 2,
	VALID = 3,
	WALLET_CREATED = 4,
	KYC_FAILED = 5,
}

export enum GrantUserPaymnents {
	NONE = 0,
	ALL = 1,
}

export enum RoleUser {
	SUPERADMIN = 1,
	ADMIN = 2,
	SP_ADMIN = 3,
	USER = 4,
}

export enum TypeUser {
	PLATFORM = 'PLATFORM',
	PROVIDER = 'PROVIDER',
	WALLET = 'WALLET',
}
