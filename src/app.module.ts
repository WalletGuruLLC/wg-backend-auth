import { Module } from '@nestjs/common';
import { UserModule } from './api/user/user.module';
import { ConfigModule } from '@nestjs/config';
import { ProviderModule } from './api/provider/provider.module';

@Module({
	imports: [ConfigModule.forRoot(), UserModule, ProviderModule],
	controllers: [],
	providers: [],
})
export class AppModule {}
