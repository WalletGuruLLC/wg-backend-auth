import { StatusMessages } from '../constants';

export function createResponse(statusCode, message) {
	if (typeof statusCode !== 'number') {
		throw new TypeError('statusCode must be a number');
	}

	const status = StatusMessages[statusCode] || 'custom';

	return {
		code: statusCode,
		status: status,
		message: message,
	};
}
