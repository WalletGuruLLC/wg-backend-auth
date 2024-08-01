import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { dynamoConnect } from './config/dbconfig';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
	await dynamoConnect();
	const app = await NestFactory.create(AppModule);

	const config = new DocumentBuilder()
		.setTitle('Paystream API')
		.setDescription('Paystream API Documentation Authentication service')
		.setVersion('1.0')
		.build();
	const document = SwaggerModule.createDocument(app, config);
	SwaggerModule.setup('docs', app, document);

	await app.listen(3000);
}
bootstrap();
