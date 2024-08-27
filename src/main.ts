import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { dynamoConnect } from './config/dbconfig';
import { AllExceptionsFilter } from './api/all-exceptions.filter';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as Sentry from '@sentry/nestjs';
import { nodeProfilingIntegration } from '@sentry/profiling-node';

async function bootstrap() {
	if (process.env.SENTRY_DSN) {
		Sentry.init({
			dsn: process.env.SENTRY_DSN,
			integrations: [nodeProfilingIntegration()],
			tracesSampleRate: 1.0, //  Capture 100% of the transactions
			profilesSampleRate: 1.0,
			environment: process.env.NODE_ENV,
		});
	}
	await dynamoConnect();
	const app = await NestFactory.create(AppModule);
	app.useGlobalFilters(new AllExceptionsFilter());

	const config = new DocumentBuilder()
		.setTitle('Paystream API Documentation')
		.setDescription(
			'Comprehensive documentation for the Paystream API, detailing the Authentication service and its endpoints.'
		)
		.addServer('http://localhost:3000/', 'Local environment')
		.addServer('https://dev.auth.walletguru.co/', 'Dev environment')
		.addBearerAuth(
			{ type: 'http', scheme: 'bearer', bearerFormat: 'JWT', in: 'header' },
			'JWT'
		)
		.setVersion('1.0')
		.build();
	const document = SwaggerModule.createDocument(app, config);
	SwaggerModule.setup('docs', app, document);

	app.enableCors({
		allowedHeaders: '*',
		origin: '*',
		credentials: true,
	});

	await app.listen(3000);
}

bootstrap();
