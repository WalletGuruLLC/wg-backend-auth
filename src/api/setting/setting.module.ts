import { forwardRef, Module } from '@nestjs/common';
import { SettingService } from './setting.service';
import { SettingController } from './setting.controller';
import { ConfigModule } from '@nestjs/config';
import { UserModule } from '../user/user.module';
@Module({
	imports: [ConfigModule, forwardRef(() => UserModule)],
	controllers: [SettingController],
	providers: [SettingService],
})
export class SettingModule {}
