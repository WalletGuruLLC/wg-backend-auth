import { Module } from '@nestjs/common';

import { ConfigModule } from '@nestjs/config';
import { ProviderController } from './controller/provider.controller';
import { ProviderService } from './service/provider.service';

@Module({
	imports: [ConfigModule],
	controllers: [ProviderController],
	providers: [ProviderService],
})
export class ProviderModule {}
