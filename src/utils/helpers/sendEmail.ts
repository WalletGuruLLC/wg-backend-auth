import * as AWS from 'aws-sdk';
import * as Sentry from "@sentry/nestjs";

export const sendEmail = async (
	toAddresses: string[],
	subject: string,
	htmlBody: string
): Promise<void> => {
	const ses = new AWS.SES({
		region: process.env.AWS_REGION,
		accessKeyId: process.env.AWS_KEY_ID,
		secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
	});

	const params = {
		Source: process.env.AWS_SES_EMAIL,
		Destination: {
			ToAddresses: toAddresses,
		},
		Message: {
			Subject: {
				Data: subject,
			},
			Body: {
				Html: {
					Data: htmlBody,
				},
			},
		},
	};

	try {
		await ses.sendEmail(params).promise();
	} catch (error) {
		Sentry.captureException(error);
		throw new Error(error.message);
	}
};
