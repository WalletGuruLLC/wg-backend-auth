import * as dynamoose from 'dynamoose';

export const UserSchema = new dynamoose.Schema(
	{
		Id: {
			type: String,
			hashKey: true,
			required: true,
		},
		Username: {
			type: String,
			required: true,
			index: {
				global: true,
				name: 'UsernameIndex',
			},
		},
		Email: {
			type: String,
			required: true,
			index: {
				global: true,
				name: 'EmailIndex',
			},
		},
		PasswordHash: {
			type: String,
			required: true,
		},
		MfaEnabled: {
			type: Boolean,
			default: false,
		},
		MfaType: {
			type: String,
			enum: ['SMS', 'TOTP'],
			default: null,
		},
		Rol: {
			type: String,
			default: 'user',
		},
		Otp: {
			type: String,
			default: '',
		},
		OtpTimestamp: {
			type: Date,
		},
	},
	{
		timestamps: {
			createdAt: 'CreateDate',
			updatedAt: 'UpdateDate',
		},
	}
);

export const UserModel = dynamoose.model('users', UserSchema, {
	create: false, // No crear tablas automáticamente
	update: false, // No actualizar tablas automáticamente
	waitForActive: false, // No esperar a que las tablas estén activas
});
