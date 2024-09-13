import {
	Injectable,
	NestMiddleware,
	HttpException,
	HttpStatus,
} from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { RoleService } from 'src/api/role/service/role.service';
import { UserService } from '../service/user.service';
import { buscarValorPorClave } from 'src/utils/helpers/findKeyValue';

@Injectable()
export class AccessControlMiddleware implements NestMiddleware {
	constructor(
		private readonly roleService: RoleService,
		private readonly authService: UserService
	) {}

	async use(req: Request, res: Response, next: NextFunction): Promise<void> {
		const authHeader = req.headers.authorization;

		if (!authHeader) {
			throw new HttpException(
				{
					statusCode: HttpStatus.UNAUTHORIZED,
					customCode: 'WGE0021',
				},
				HttpStatus.UNAUTHORIZED
			);
		}

		const userCognito = await this.authService.getUserInfo(authHeader);
		const user = await this.authService.findOneByEmail(
			userCognito?.UserAttributes?.[0]?.Value
		);
		const userRoleId = user.roleId;

		const requestedModuleId = this.getModuleIdFromPath(req.route.path);
		const requiredMethod = req.method;

		const role = await this.roleService.getRoleInfo(userRoleId);

		if (user?.type === 'PROVIDER') {
			console.log('requestedModuleId', user?.type, requestedModuleId);
			if (requestedModuleId == 'SP95') {
				console.log('serviceProviderId', user?.serviceProviderId, user?.email);

				if (!user?.serviceProviderId) {
					throw new HttpException(
						{
							statusCode: HttpStatus.BAD_REQUEST,
							customCode: 'WGE0130',
						},
						HttpStatus.BAD_REQUEST
					);
				}

				console.log('role?.PermissionModules', role?.PermissionModules);

				const permissionModule = role?.PermissionModules?.find(
					module => module[requestedModuleId]
				);

				if (!permissionModule) {
					throw new HttpException(
						{
							statusCode: HttpStatus.UNAUTHORIZED,
							customCode: 'WGE0131',
						},
						HttpStatus.UNAUTHORIZED
					);
				}

				const serviceProviderAccessLevel = buscarValorPorClave(
					permissionModule[requestedModuleId],
					user?.serviceProviderId
				);

				if (!serviceProviderAccessLevel) {
					throw new HttpException(
						{
							statusCode: HttpStatus.UNAUTHORIZED,
							customCode: 'WGE0132',
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

				if ((serviceProviderAccessLevel & requiredAccess) !== requiredAccess) {
					throw new HttpException(
						{
							statusCode: HttpStatus.UNAUTHORIZED,
							customCode: 'WGE0038',
						},
						HttpStatus.UNAUTHORIZED
					);
				}

				next();
				return;
			}
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
