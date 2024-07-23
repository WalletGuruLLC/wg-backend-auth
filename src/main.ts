import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { dynamoConnect } from './config/dbconfig';

async function bootstrap() {
	await dynamoConnect();
	const app = await NestFactory.create(AppModule);
	await app.listen(3000);
}
bootstrap();
