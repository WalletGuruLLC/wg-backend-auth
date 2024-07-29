import { Module } from '@nestjs/common';
import { UserModule } from './api/user/user.module';
import { ConfigModule } from '@nestjs/config';

@Module({
	imports: [ConfigModule.forRoot(), UserModule],
	controllers: [],
	providers: [],
})
export class AppModule {}
