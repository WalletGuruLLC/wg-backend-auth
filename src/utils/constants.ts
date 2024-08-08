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
	WGE0001: {
		message: 'Incorrect password',
		description:
			'The entered password does not match the one registered in the system.',
	},
	WGE0002: {
		message: 'User not found',
		description:
			'There is no account associated with the entered email or username.',
	},
	WGE0003: {
		message: 'User already exists',
		description:
			'An account is already registered with the provided email or username.',
	},
	WGE0004: {
		message: 'Email not verified',
		description: 'The account exists, but the email has not been verified.',
	},
	WGE0005: {
		message: 'Incorrect verification code',
		description: 'The entered verification code is incorrect or has expired.',
	},
	WGE0006: {
		message: 'Session expired',
		description: 'The authentication session has expired, please log in again.',
	},
	WGE0007: {
		message: 'Incorrect old password',
		description: 'The current password entered is incorrect.',
	},
	WGE0008: {
		message: 'New password not valid',
		description:
			'The new password does not meet the established security requirements.',
	},
	WGE0009: {
		message: 'Password changed successfully',
		description: 'The password has been changed successfully.',
	},
	WGE0010: {
		message: 'Error sending verification email',
		description:
			'There was a problem sending the verification email. Please try again.',
	},
	WGE0011: {
		message: 'Invalid reset token',
		description: 'The entered password reset token is invalid or has expired.',
	},
	WGE0012: {
		message: 'Password reset successfully',
		description: 'The password has been reset successfully.',
	},
	WGE0013: {
		message: 'User registered successfully',
		description:
			'The user has been registered successfully. A verification email has been sent.',
	},
	WGE0014: {
		message: 'Login successful',
		description: 'The user has logged in successfully.',
	},
	WGE0015: {
		message: 'Two-factor authentication error',
		description:
			'Two-factor authentication failed due to an incorrect code or technical issue.',
	},
	WGE0016: {
		message: 'Internal server error',
		description:
			'An unexpected error occurred on the server. Please try again later.',
	},
	WGE0017: {
		message: 'Invalid user type',
		description: 'The type of user entered is invalid or does not correspond.',
	},
};
