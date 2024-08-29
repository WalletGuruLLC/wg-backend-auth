import {
	MiddlewareConsumer,
	Module,
	NestModule,
	forwardRef,
} from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { RoleController } from './controller/role.controller';
import { RoleService } from './service/role.service';
import { CognitoAuthGuard } from '../user/guard/cognito-auth.guard';
import { UserModule } from '../user/user.module';
import { AccessControlMiddleware } from '../user/guard/access-control-guard';
import { ProviderModule } from '../provider/provider.module';
@Module({
	imports: [ConfigModule, forwardRef(() => UserModule), ProviderModule],
	controllers: [RoleController],
	providers: [RoleService, CognitoAuthGuard],
	exports: [RoleService],
})
export class RoleModule implements NestModule {
	configure(consumer: MiddlewareConsumer) {
		consumer.apply(AccessControlMiddleware).forRoutes(RoleController);
	}
}
