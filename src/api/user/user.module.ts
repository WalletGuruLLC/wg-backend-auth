import {
	Module,
	NestModule,
	MiddlewareConsumer,
	RequestMethod,
	forwardRef,
} from '@nestjs/common';
import { UserController } from './controller/user.controller';
import { UserService } from './service/user.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { SqsService } from './sqs/sqs.service';
import { AccessControlMiddleware } from './guard/access-control-guard';
import { RoleModule } from '../role/role.module';

@Module({
	imports: [ConfigModule, forwardRef(() => RoleModule)],
	controllers: [UserController],
	providers: [UserService, SqsService, ConfigService],
	exports: [UserService, ConfigService],
})
export class UserModule implements NestModule {
	usersPath = 'api/v1/users';
	configure(consumer: MiddlewareConsumer) {
		consumer.apply(AccessControlMiddleware).forRoutes(
			{ path: `${this.usersPath}/register`, method: RequestMethod.POST },
			{ path: `${this.usersPath}/:id`, method: RequestMethod.PUT },
			{ path: `${this.usersPath}/`, method: RequestMethod.GET },
			{
				path: `${this.usersPath}/update-status/:id`,
				method: RequestMethod.PATCH,
			}
		);
	}
}
