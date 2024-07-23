import * as dynamoose from 'dynamoose';

export const UserSchema = new dynamoose.Schema(
	{
		Id: {
			type: Number,
			hashKey: true,
			required: true,
		},
		Username: {
			type: String,
			required: true,
		},
		Email: {
			type: String,
			required: true,
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
	},
	{
		timestamps: {
			createdAt: 'CreateDate',
			updatedAt: 'UpdateDate',
		},
	}
);
