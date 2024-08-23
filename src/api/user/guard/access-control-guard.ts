import {
	Injectable,
	NestMiddleware,
	ForbiddenException,
	HttpException,
	HttpStatus,
} from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { RoleService } from 'src/api/role/service/role.service';
import { UserService } from '../service/user.service';
import { errorCodes } from 'src/utils/constants';

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
					customMessage: errorCodes.WGE0021?.description,
					customMessageEs: errorCodes.WGE0021?.descriptionEs,
				},
				HttpStatus.UNAUTHORIZED
			);
		}

		const userCognito = await this.authService.getUserInfo(authHeader);
		const user = await this.authService.findOneByEmail(
			userCognito?.UserAttributes?.[0]?.Value
		);
		const userRoleId = user.RoleId;

		// Obtener la ruta solicitada
		const requestedModuleId = this.getModuleIdFromPath(req.route.path);
		const requiredMethod = req.method;

		console.log(
			'requestedModuleId',
			requestedModuleId,
			'requiredMethod',
			requiredMethod
		);

		// Obtener la información del rol del usuario
		const role = await this.roleService.getRoleInfo(userRoleId);

		// Verificar si el módulo existe en los permisos del usuario
		const userAccessLevel = role.Modules[requestedModuleId];
		if (userAccessLevel === undefined) {
			throw new ForbiddenException(
				`No tienes permisos en el módulo ${requestedModuleId}.`
			);
		}

		const accessMap = {
			GET: 1,
			POST: 2,
			PUT: 4,
			DELETE: 8,
		};

		const requiredAccess = accessMap[requiredMethod];

		if ((userAccessLevel & requiredAccess) !== requiredAccess) {
			throw new ForbiddenException(
				'No tienes permiso para realizar esta acción.'
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
