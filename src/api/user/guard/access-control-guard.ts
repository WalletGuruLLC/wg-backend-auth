import {
	Injectable,
	NestMiddleware,
	HttpException,
	HttpStatus,
} from '@nestjs/common';
import { Request, NextFunction } from 'express';
import { RoleService } from 'src/api/role/service/role.service';
import { UserService } from '../service/user.service';
import { errorCodes } from 'src/utils/constants';

@Injectable()
export class AccessControlMiddleware implements NestMiddleware {
	constructor(
		private readonly roleService: RoleService,
		private readonly authService: UserService
	) {}

	async use(req: Request, res, next: NextFunction): Promise<void> {
		const authHeader = req.headers.authorization;

		if (!authHeader) {
			throw new HttpException(
				{
					statusCode: HttpStatus.UNAUTHORIZED,
					customCode: 'WGE0021',
					customMessage: errorCodes.WGE0021?.description,
					customMessageEs: errorCodes.WGE0021?.descriptionEs,
				},
				HttpStatus.UNAUTHORIZED
			);
		}

		try {
			const userCognito = await this.authService.getUserInfo(authHeader);
			const user = await this.authService.findOneByEmail(
				userCognito?.UserAttributes?.[0]?.Value
			);

			if (!user) {
				throw new HttpException(
					{
						statusCode: HttpStatus.UNAUTHORIZED,
						customCode: 'WGE0021',
						customMessage: errorCodes.WGE0021?.description,
						customMessageEs: errorCodes.WGE0021?.descriptionEs,
					},
					HttpStatus.UNAUTHORIZED
				);
			}

			const userRoleId = user.roleId;
			const requestedModuleId = this.getModuleIdFromPath(req.route.path);
			const requiredMethod = req.method;

			const role = await this.roleService.getRoleInfo(userRoleId);

			if (!role) {
				throw new HttpException(
					{
						statusCode: HttpStatus.NOT_FOUND,
						customCode: 'WGE0046',
						customMessage: errorCodes.WGE0046?.description,
						customMessageEs: errorCodes.WGE0046?.descriptionEs,
					},
					HttpStatus.NOT_FOUND
				);
			}

			const userAccessLevels = role?.Modules[requestedModuleId];

			if (!userAccessLevels && user.type !== 'WALLET') {
				throw new HttpException(
					{
						statusCode: HttpStatus.UNAUTHORIZED,
						customCode: 'WGE0039',
						customMessage: errorCodes.WGE0039?.description,
						customMessageEs: errorCodes.WGE0039?.descriptionEs,
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

			if (typeof userAccessLevels === 'object') {
				let hasAccess = false;

				for (const [, level] of Object.entries(userAccessLevels)) {
					if (level >= requiredAccess) {
						hasAccess = true;
						break;
					}
				}

				if (!hasAccess && user.type !== 'WALLET') {
					throw new HttpException(
						{
							statusCode: HttpStatus.UNAUTHORIZED,
							customCode: 'WGE0038',
							customMessage: errorCodes.WGE0038?.description,
							customMessageEs: errorCodes.WGE0038?.descriptionEs,
						},
						HttpStatus.UNAUTHORIZED
					);
				}
			} else {
				if (
					userAccessLevels < 8 ||
					((userAccessLevels & requiredAccess) !== requiredAccess &&
						user.type !== 'WALLET')
				) {
					throw new HttpException(
						{
							statusCode: HttpStatus.UNAUTHORIZED,
							customCode: 'WGE0038',
							customMessage: errorCodes.WGE0038?.description,
							customMessageEs: errorCodes.WGE0038?.descriptionEs,
						},
						HttpStatus.UNAUTHORIZED
					);
				}
			}
		} catch (error) {
			console.error('Access Control Middleware Error:', error?.message);
			throw new HttpException(
				{
					statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
					customCode: 'WGE0035',
					customMessage: errorCodes.WGE0035?.description,
					customMessageEs: errorCodes.WGE0035?.descriptionEs,
				},
				HttpStatus.INTERNAL_SERVER_ERROR
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
