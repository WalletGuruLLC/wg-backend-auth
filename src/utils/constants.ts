export const HttpStatus = {
	OK: 200,
	CREATED: 201,
	ACCEPTED: 202,
	NO_CONTENT: 204,
	BAD_REQUEST: 400,
	UNAUTHORIZED: 401,
	FORBIDDEN: 403,
	NOT_FOUND: 404,
	INTERNAL_SERVER_ERROR: 500,
	BAD_GATEWAY: 502,
	SERVICE_UNAVAILABLE: 503,
};

export const StatusMessages = {
	[HttpStatus.OK]: 'success',
	[HttpStatus.CREATED]: 'created',
	[HttpStatus.ACCEPTED]: 'accepted',
	[HttpStatus.NO_CONTENT]: 'no content',
	[HttpStatus.BAD_REQUEST]: 'bad request',
	[HttpStatus.UNAUTHORIZED]: 'unauthorized',
	[HttpStatus.FORBIDDEN]: 'forbidden',
	[HttpStatus.NOT_FOUND]: 'not found',
	[HttpStatus.INTERNAL_SERVER_ERROR]: 'internal server error',
	[HttpStatus.BAD_GATEWAY]: 'bad gateway',
	[HttpStatus.SERVICE_UNAVAILABLE]: 'service unavailable',
};

export const customCodes = {
	r0001: {
		message: 'Incorrect password',
		description:
			'The entered password does not match the one registered in the system.',
	},
	r0002: {
		message: 'User not found',
		description:
			'There is no account associated with the entered email or username.',
	},
	r0003: {
		message: 'User already exists',
		description:
			'An account is already registered with the provided email or username.',
	},
	r0004: {
		message: 'Email not verified',
		description: 'The account exists, but the email has not been verified.',
	},
	r0005: {
		message: 'Incorrect verification code',
		description: 'The entered verification code is incorrect or has expired.',
	},
	r0006: {
		message: 'Session expired',
		description: 'The authentication session has expired, please log in again.',
	},
	r0007: {
		message: 'Incorrect old password',
		description: 'The current password entered is incorrect.',
	},
	r0008: {
		message: 'New password not valid',
		description:
			'The new password does not meet the established security requirements.',
	},
	r0009: {
		message: 'Password changed successfully',
		description: 'The password has been changed successfully.',
	},
	r0010: {
		message: 'Error sending verification email',
		description:
			'There was a problem sending the verification email. Please try again.',
	},
	r0011: {
		message: 'Invalid reset token',
		description: 'The entered password reset token is invalid or has expired.',
	},
	r0012: {
		message: 'Password reset successfully',
		description: 'The password has been reset successfully.',
	},
	r0013: {
		message: 'User registered successfully',
		description:
			'The user has been registered successfully. A verification email has been sent.',
	},
	r0014: {
		message: 'Login successful',
		description: 'The user has logged in successfully.',
	},
	r0015: {
		message: 'Two-factor authentication error',
		description:
			'Two-factor authentication failed due to an incorrect code or technical issue.',
	},
	r0016: {
		message: 'Internal server error',
		description:
			'An unexpected error occurred on the server. Please try again later.',
	},
};
