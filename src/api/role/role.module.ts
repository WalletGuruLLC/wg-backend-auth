import { Module } from '@nestjs/common';

import { ConfigModule } from '@nestjs/config';
import { RoleController } from './controller/role.controller';
import { RoleService } from './service/role.service';

@Module({
	imports: [ConfigModule],
	controllers: [RoleController],
	providers: [RoleService],
})
export class RoleModule {}
