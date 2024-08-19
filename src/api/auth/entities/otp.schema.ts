import * as dynamoose from 'dynamoose';

export const OtpSchema = new dynamoose.Schema(
	{
		email: {
			type: String,
			required: true,
			index: {
				global: true,
				name: 'emailIndex',
			},
		},
		otp: {
			type: String,
			required: true,
			index: {
				global: true,
				name: 'otpIndex',
			},
		},
		token: {
			type: String,
		},
		createdAt: {
			type: Date,
			required: true,
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

export const OtpModel = dynamoose.model('otps', OtpSchema, {
	expires: 60 * 5,
});
