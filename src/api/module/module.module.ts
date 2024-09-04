import { Module } from '@nestjs/common';
import { ModuleService } from './module.service';
import { ModuleController } from './module.controller';
import { CognitoAuthGuard } from '../user/guard/cognito-auth.guard';
import { UserModule } from '../user/user.module';

@Module({
	imports: [UserModule],
	controllers: [ModuleController],
	providers: [ModuleService, CognitoAuthGuard],
})
export class ModuleModule {}
