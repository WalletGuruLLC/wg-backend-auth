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
