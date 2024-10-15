import {
	Injectable,
	NestMiddleware,
	HttpException,
	HttpStatus,
} from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { RoleService } from 'src/api/role/service/role.service';
import { UserService } from '../service/user.service';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AccessControlMiddleware implements NestMiddleware {
	constructor(
		private readonly roleService: RoleService,
		private readonly authService: UserService,
		private readonly configService: ConfigService
	) {}

	async use(req: Request, res: Response, next: NextFunction): Promise<void> {
		const authHeader = req.headers.authorization;

		if (!authHeader) {
			throw new HttpException(
				{
					statusCode: HttpStatus.UNAUTHORIZED,
					customCode: 'WGE0126',
				},
				HttpStatus.UNAUTHORIZED
			);
		}

		const secret = this.configService.get<string>('APP_SECRET');

		if (`Bearer ${secret}` == authHeader) {
			next();
			return;
		}

		const userCognito = await this.authService.getUserInfo(authHeader);
		const user = await this.authService.findOneByEmail(
			userCognito?.UserAttributes?.[0]?.Value
		);
		const userRoleId = user.roleId;

		const requestedModuleId = this.getModuleIdFromPath(req.route.path);
		const requiredMethod = req.method;

		const role = await this.roleService.getRoleInfo(userRoleId);

		if (
			req.path === `/api/v1/providers/${user.serviceProviderId}` &&
			requiredMethod === 'GET'
		) {
			next();
			return;
		}

		if (user?.type === 'PLATFORM' && requestedModuleId == 'SP95') {
			next();
			return;
		}
		const userAccessLevel = role?.Modules[requestedModuleId];

		if (userAccessLevel === undefined && user.type !== 'WALLET') {
			throw new HttpException(
				{
					statusCode: HttpStatus.UNAUTHORIZED,
					customCode: 'WGE0039',
				},
				HttpStatus.UNAUTHORIZED
			);
		}

		const accessMap = {
			GET: 8,
			POST: 4,
			PUT: 2,
			PATCH: 1,
			DELETE: 1,
		};

		const requiredAccess = accessMap[requiredMethod];

		if (
			userAccessLevel < 8 ||
			((userAccessLevel & requiredAccess) !== requiredAccess &&
				user.type !== 'WALLET')
		) {
			throw new HttpException(
				{
					statusCode: HttpStatus.UNAUTHORIZED,
					customCode: 'WGE0038',
				},
				HttpStatus.UNAUTHORIZED
			);
		}

		next();
	}

	private getModuleIdFromPath(path: string): string {
		const moduleIdMap = {
			'/api/v1/users': 'U783',
			'/api/v1/roles': 'R949',
			'/api/v1/providers': 'SP95',
			'/api/v1/wallets': 'W325',
		};

		const normalizedPath = path.split('/').slice(0, 4).join('/');

		return moduleIdMap[normalizedPath] || '';
	}
}
