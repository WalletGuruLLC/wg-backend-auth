import {
	forwardRef,
	MiddlewareConsumer,
	Module,
	NestModule,
	RequestMethod,
} from '@nestjs/common';

import { ConfigModule } from '@nestjs/config';
import { ProviderController } from './controller/provider.controller';
import { ProviderService } from './service/provider.service';
import { CognitoAuthGuard } from '../user/guard/cognito-auth.guard';
import { AccessControlMiddleware } from '../user/guard/access-control-guard';
import { UserModule } from '../user/user.module';
import { RoleModule } from '../role/role.module';
import { PaymentController } from './controller/payment.controller';
@Module({
	imports: [
		ConfigModule,
		forwardRef(() => UserModule),
		forwardRef(() => RoleModule),
	],
	controllers: [ProviderController, PaymentController],
	providers: [ProviderService, CognitoAuthGuard],
	exports: [ProviderService],
})
export class ProviderModule implements NestModule {
	configure(consumer: MiddlewareConsumer) {
		consumer
			.apply(AccessControlMiddleware)
			.exclude({
				path: 'api/v1/payments/list/payment-parameters',
				method: RequestMethod.GET,
			})
			.forRoutes(ProviderController, PaymentController);
	}
}
