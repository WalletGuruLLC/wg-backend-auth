import * as dynamoose from 'dynamoose';

export const OtpSchema = new dynamoose.Schema(
	{
		Email: {
			type: String,
			required: true,
			index: {
				global: true,
				name: 'emailIndex',
			},
		},
		Otp: {
			type: String,
			required: true,
			index: {
				global: true,
				name: 'otpIndex',
			},
		},
		Token: {
			type: String,
		},
		CreatedAt: {
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

export const OtpModel = dynamoose.model('Otps', OtpSchema, {
	expires: 60 * 5,
});
