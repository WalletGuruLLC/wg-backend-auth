import * as dynamoose from 'dynamoose';
import { User } from './user.entity';
import { MfaTypeUser, RoleUser, StateUser, TypeUser } from '../dto/user.enums';

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
			enum: Object.values(MfaTypeUser),
			default: MfaTypeUser.TOTP,
		},
		type: {
			type: String,
			enum: Object.values(TypeUser),
			default: TypeUser.PLATFORM,
		},
		RoleId: {
			type: Number,
			enum: Object.values(RoleUser),
			default: RoleUser.USER,
		},
		Active: {
			type: Boolean,
			default: true,
		},
		State: {
			type: Number,
			enum: Object.values(StateUser),
			default: StateUser.VERIFY,
		},
		Picture: {
			type: String,
			default: '',
		},
		SendSms: {
			type: Boolean,
			default: false,
		},
		SendEmails: {
			type: Boolean,
			default: true,
		},
		ServiceProviderId: {
			type: Number,
			default: 0,
		},
		LastSignIn: {
			type: Date,
			default: null,
		},
		Otp: {
			type: String,
			default: '',
		},
		OtpTimestamp: {
			type: Date,
			default: () => new Date(),
		},
	},
	{
		timestamps: {
			createdAt: 'CreateDate',
			updatedAt: 'UpdateDate',
		},
	}
);

// Asocia el modelo con la clase User
export const UserModel = dynamoose.model<User>('users', UserSchema, {
	create: false,
	update: false,
	waitForActive: false,
});
