import { Module } from '@nestjs/common';
import { UserController } from './controller/user.controller';
import { UserService } from './service/user.service';
import { ConfigModule } from '@nestjs/config';

@Module({
	imports: [ConfigModule],
	controllers: [UserController],
	providers: [UserService],
})
export class UserModule {}
