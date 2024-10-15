import {
	Injectable,
	CanActivate,
	ExecutionContext,
	HttpException,
	HttpStatus,
} from '@nestjs/common';
import { UserService } from '../service/user.service';
import * as Sentry from '@sentry/nestjs';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class CognitoAuthGuard implements CanActivate {
	constructor(
		private readonly authService: UserService,
		private readonly configService: ConfigService
	) {}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		const request = context.switchToHttp().getRequest();
		const authHeader = request.headers.authorization;

		if (!authHeader) {
			throw new HttpException(
				{
					statusCode: HttpStatus.UNAUTHORIZED,
					customCode: 'WGE0021',
				},
				HttpStatus.UNAUTHORIZED
			);
		}

		try {
			const secret = this.configService.get<string>('APP_SECRET');
			if (`Bearer ${secret}` == authHeader) {
				request.user = 'APP';
				return true;
			}
			const user = await this.authService.getUserInfo(authHeader);
			request.user = user;
			request.token = authHeader;
			return true;
		} catch (error) {
			Sentry.captureException(error);
			throw new HttpException(
				{
					statusCode: HttpStatus.UNAUTHORIZED,
					customCode: 'WGE0021',
				},
				HttpStatus.UNAUTHORIZED
			);
		}
	}
}
