import {
	forwardRef,
	MiddlewareConsumer,
	Module,
	NestModule,
	RequestMethod,
} from '@nestjs/common';
import { HealthController } from './controller/health.controller';
import { AccessControlMiddleware } from '../user/guard/access-control-guard';
import { ConfigModule } from '@nestjs/config';
import { HealthService } from './service/health.service';
import { RoleModule } from '../role/role.module';
import { CognitoAuthGuard } from '../user/guard/cognito-auth.guard';
import { UserModule } from '../user/user.module';
import { ProviderController } from '../provider/controller/provider.controller';

@Module({
	imports: [
		ConfigModule,
		forwardRef(() => UserModule),
		forwardRef(() => RoleModule),
	],
	controllers: [HealthController],
	providers: [HealthService, CognitoAuthGuard],
	exports: [HealthService],
})
export class HealthModule implements NestModule {
	usersPath = 'api/v1/health-check';

	configure(consumer: MiddlewareConsumer) {
		consumer.apply(AccessControlMiddleware).forRoutes({
			path: `${this.usersPath}/uptime`,
			method: RequestMethod.GET,
		});
	}
}

console.log('HealthModule', ProviderController);
