import { NestFactory, Reflector } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { ClassSerializerInterceptor, ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import { AllExceptionsFilter } from './common/exceptions/globalExceptionFilter';
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser());
  app.use(helmet());
  app.use(compression());
  app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100, // 
    standardHeaders: 'draft-8',
    legacyHeaders: false,
  }));
  app.useGlobalInterceptors(new ClassSerializerInterceptor(app.get(Reflector)))
  app.useGlobalFilters(new AllExceptionsFilter());
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
    transformOptions: {
      enableImplicitConversion: true,
    },
  }));

  const apiVersion = process.env.API_VERSION || 'v1';
  app.setGlobalPrefix(`api/${apiVersion}`);

  const configService = app.get(ConfigService);
  const appPort = configService.get<number>('PORT') || 8000;
  const appHost = configService.get<string>('APP_HOST') || 'http://localhost';

  const allowedOrigins = (configService.get<string>('ALLOWED_ORIGINS') || 'http://localhost:3000')
    ?.split(',')
    .map(origin => origin.trim()).filter(origin => origin !== appHost);

  console.log('Allowed Origins for CORS:', allowedOrigins);
  app.enableCors({
    origin: allowedOrigins,
    methods: ['GET', 'PUT', 'PATCH', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  });
  const config = new DocumentBuilder()
    .setTitle('Employee Management System (EMS) API - Developed by Asoh Yannick, Backend Software Engineer | TypeScript • NodeJS • NestJS • PostgreSQL • JsonWebToken (JWT)')
    .setDescription(`
    Welcome to the comprehensive RESTful API documentation for the Employee Management System (EMS). 
    This documentation covers all available endpoints, including authentication, 
    employee profiles, departments, job roles, payroll & salaries, inventory, sales, reporting, 
    and administrative operations.

    Designed for developers, engineers, and integrators, this documentation provides detailed 
    information on request/response schemas, authentication requirements, and error handling. 
    Use this guide to integrate, maintain, or extend EMS backend services effectively.
  `)
    .setVersion('1.0')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup(`api/${apiVersion}/docs`, app, document);

  // Graceful shutdown
  app.enableShutdownHooks();

  await app.listen(appPort);
  console.log(`🚀 Server running at ${appHost}:${appPort}/api/${apiVersion}`);
  console.log(`📖 Swagger docs: ${appHost}:${appPort}/api/${apiVersion}/docs`);
}
bootstrap();