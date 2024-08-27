import {
	Module,
	NestModule,
	MiddlewareConsumer,
	RequestMethod,
	forwardRef,
} from '@nestjs/common';
import { UserController } from './controller/user.controller';
import { UserService } from './service/user.service';
import { ConfigModule } from '@nestjs/config';
import { SqsService } from './sqs/sqs.service';
import { AccessControlMiddleware } from './guard/access-control-guard';
import { RoleModule } from '../role/role.module';

@Module({
	imports: [ConfigModule, forwardRef(() => RoleModule)],
	controllers: [UserController],
	providers: [UserService, SqsService],
	exports: [UserService],
})
export class UserModule implements NestModule {
	usersPath = 'api/v1/users';
	configure(consumer: MiddlewareConsumer) {
		consumer.apply(AccessControlMiddleware).forRoutes(
			{ path: `${this.usersPath}/:id`, method: RequestMethod.GET },
			{ path: `${this.usersPath}/:id`, method: RequestMethod.PATCH },
			{ path: `${this.usersPath}/:id`, method: RequestMethod.DELETE },
			{ path: `${this.usersPath}/`, method: RequestMethod.GET },
			{
				path: `${this.usersPath}/update-status/:id`,
				method: RequestMethod.PATCH,
			}
		);
	}
}
