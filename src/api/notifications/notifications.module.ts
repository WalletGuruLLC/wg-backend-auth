import { Module, forwardRef } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { NotificationsController } from './controller/notifications.controller';
import { CognitoAuthGuard } from '../user/guard/cognito-auth.guard';
import { UserModule } from '../user/user.module';
import { NotificationsService } from './service/notifications.service';
@Module({
	imports: [ConfigModule, forwardRef(() => UserModule)],
	controllers: [NotificationsController],
	providers: [NotificationsService, CognitoAuthGuard],
	exports: [NotificationsService],
})
export class NotificationsModule {}
