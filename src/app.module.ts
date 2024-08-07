import { Module } from '@nestjs/common';
import { UserModule } from './api/user/user.module';
import { ConfigModule } from '@nestjs/config';
import { ProviderModule } from './api/provider/provider.module';
import { RoleModule } from './api/role/role.module';

@Module({
	imports: [ConfigModule.forRoot(), UserModule, ProviderModule, RoleModule],
	controllers: [],
	providers: [],
})
export class AppModule {}
