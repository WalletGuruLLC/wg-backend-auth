import { Module } from '@nestjs/common';
import { UserModule } from './api/user/user.module';
import { ConfigModule } from '@nestjs/config';
import { ProviderModule } from './api/provider/provider.module';
import { RoleModule } from './api/role/role.module';
import { ModuleModule } from './api/module/module.module';
import { SettingModule } from './api/setting/setting.module';
import { NotificationsModule } from './api/notifications/notifications.module';
import { SecretsModule } from './secrets.module';
import { HealthModule } from './api/health/health.module';
@Module({
	imports: [
		SecretsModule,
		ConfigModule.forRoot(),
		UserModule,
		ProviderModule,
		RoleModule,
		ModuleModule,
		SettingModule,
		NotificationsModule,
		HealthModule,
	],
	controllers: [],
	providers: [],
})
export class AppModule {}
