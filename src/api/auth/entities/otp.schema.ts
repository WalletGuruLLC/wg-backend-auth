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
				name: 'OtpIndex',
			},
		},
		Token: {
			type: String,
		},
		RefreshToken: {
			type: String,
		},
		CreatedAt: {
			type: Date,
			required: true,
			default: () => new Date(),
		},
		Ttl: {
			type: Number,
		},
	},
	{
		timestamps: {
			createdAt: 'CreateDate',
			updatedAt: 'UpdateDate',
		},
	}
);

// export const OtpModel = dynamoose.model('Otps', OtpSchema);
