import {
	ExceptionFilter,
	Catch,
	ArgumentsHost,
	HttpException,
	HttpStatus,
} from '@nestjs/common';
import * as Sentry from '@sentry/nestjs';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
	catch(exception: any, host: ArgumentsHost) {
		Sentry.captureException(exception);
		const ctx = host.switchToHttp();
		const response = ctx.getResponse();
		let status = HttpStatus.INTERNAL_SERVER_ERROR;
		if (exception instanceof HttpException) {
			status = exception.getStatus();
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
		} else {
			throw exception;
		}
	}
}
