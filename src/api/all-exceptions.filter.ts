import {
	ExceptionFilter,
	Catch,
	ArgumentsHost,
	HttpException,
	HttpStatus,
	BadRequestException,
} from '@nestjs/common';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
	catch(exception: HttpException, host: ArgumentsHost) {
		const ctx = host.switchToHttp();
		const response = ctx.getResponse();
		const status =
			exception instanceof HttpException
				? exception.getStatus()
				: HttpStatus.INTERNAL_SERVER_ERROR;

		let customResponse: any = {
			statusCode: status,
			customCode: exception.getResponse()['customCode'],
			customMessage:
				exception.getResponse()['description'] ||
				exception.getResponse()['customMessage'],
			customMessageEs:
				exception.getResponse()['descriptionEs'] ||
				exception.getResponse()['customMessageEs'],
		};
		const message = Array.isArray(exception.getResponse()['message'])
			? exception.getResponse()['message'].join(', ')
			: exception.getResponse()['message'];
		if (message) {
			customResponse = {
				...customResponse,
				message: message,
			};
		}

		response.status(status).json(customResponse);
	}
}
