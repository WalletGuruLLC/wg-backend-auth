import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { UserService } from '../service/user.service';

@Injectable()
export class CognitoAuthGuard implements CanActivate {
	constructor(private readonly authService: UserService) {}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		const request = context.switchToHttp().getRequest();
		const authHeader = request.headers.authorization;

		if (!authHeader) {
			return false;
		}

		try {
			const user = await this.authService.getUserInfo(authHeader);
			request.user = user;
			request.token = authHeader;
			return true;
		} catch (error) {
			return false;
		}
	}
}
