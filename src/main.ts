import { Logger, ValidationPipe, VersioningType } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as cookieParser from 'cookie-parser';
import * as basicAuth from 'express-basic-auth';
import * as morgan from 'morgan';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe({ transform: true }));
  app.setGlobalPrefix('api');
  app.enableVersioning({
    type: VersioningType.URI,
  });
  app.use(cookieParser());

  const logger = new Logger('HTTP');

  // Custom stream to use NestJS logger
  const stream = {
    write: (message: string) => logger.log(message.trim()),
  };

  app.use(morgan('combined', { stream }));

  const configService = app.get(ConfigService);

  const PORT = configService.get<number>('PORT');
  const SWAGGER_USER = configService.get<string>('SWAGGER_USER');
  const SWAGGER_PASSWORD = configService.get<string>('SWAGGER_PASSWORD');

  app.use(
    ['/api/docs'],
    basicAuth({
      challenge: true,
      users: {
        [SWAGGER_USER]: SWAGGER_PASSWORD,
      },
    }),
  );

  const options = new DocumentBuilder()
    .setTitle('ImpactNet Auth Service API')
    .setVersion('1.0')
    .addServer(`http://localhost:${PORT || 8080}/`, 'Local environment')
    .build();

  const document = SwaggerModule.createDocument(app, options);
  SwaggerModule.setup('/api/docs', app, document);

  app.enableCors({
    origin: true,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    allowedHeaders:
      'Content-Type, Accept,Authorization,X-API-Key, Access-Control-Allow-Origin, Access-Control-Allow-Credentials, Access-Control-Allow-Headers, Access-Control-Allow-Methods',
    credentials: true,
  });

  await app.listen(PORT || 8080);
}

bootstrap().then(() => {
  console.log('Application started successfully.');
})
  .catch((error) => {
    console.error('Error starting the application:', error);
    process.exit(1);
  });
