import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { getConnectionToken, MongooseModule } from '@nestjs/mongoose';
import { AuthModule } from '../src/auth/auth.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { Connection, connection } from 'mongoose';

describe('AuthController (e2e)', () => {
  let app: INestApplication;
  let mongod: MongoMemoryServer;
  let connection: Connection;

  // Настраиваем in-memory MongoDB и приложение
  beforeAll(async () => {
    mongod = await MongoMemoryServer.create();
    const uri = mongod.getUri();

    const module: TestingModule = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true, // Делаем ConfigModule глобальным
          load: [
            () => ({
              JWT_SECRET: 'test-secret', // Временный секрет для тестов
              JWT_ACCESS_TOKEN_EXPIRES_IN: '1h',
              JWT_REFRESH_TOKEN_EXPIRES_IN: '7d',
            }),
          ],
        }),
        MongooseModule.forRoot(uri), // Подключаемся к in-memory базе
        JwtModule.registerAsync({
          useFactory: (configService: ConfigService) => ({
            secret: configService.get('JWT_SECRET'),
            signOptions: {
              expiresIn: configService.get('JWT_ACCESS_TOKEN_EXPIRES_IN'),
            },
          }),
          inject: [ConfigService],
        }),
        AuthModule,
      ],
    }).compile();

    app = module.createNestApplication();
    connection = module.get(getConnectionToken());
    await app.init();
  });

  beforeEach(async () => {
    await connection.db?.dropDatabase();
  });

  // Закрываем приложение и базу после тестов
  afterAll(async () => {
    if (app) await app.close();
    if (mongod) await mongod.stop();
  });

  // Тест для POST /auth/register
  it('POST /auth/register should register a new user', async () => {
    const response = await request(app.getHttpServer())
      .post('/auth/register')
      .send({
        email: 'test@example.com',
        password: 'password123',
        name: 'Test User',
      })
      .expect(201); // Ожидаем статус 201 Created

    expect(response.body).toEqual({
      message: 'User registered successfully',
      userId: expect.any(String),
      email: 'test@example.com',
    });
  });

  // Test for POST /auth/register error
  it('POST /auth/register should return 400 if email is already taken', async () => {
    await request(app.getHttpServer())
      .post('/auth/register')
      .send({
        email: 'test@example.com',
        password: 'password123',
        name: 'Test User',
      })
      .expect(201);

    const response = await request(app.getHttpServer())
      .post('/auth/register')
      .send({
        email: 'test@example.com',
        password: 'password123',
        name: 'Test User',
      })
      .expect(400);

    expect(response.body).toEqual({
      error: 'Bad Request',
      message: 'Email already exists',
      statusCode: 400,
    });
  });

  it('POST /auth/login should authenticate user', async () => {
    await request(app.getHttpServer())
      .post('/auth/register')
      .send({
        email: 'test@example.com',
        password: 'password123',
        name: 'Test User',
      })
      .expect(201);

    const response = await request(app.getHttpServer())
      .post('/auth/login')
      .send({
        email: 'test@example.com',
        password: 'password123',
      })
      .expect(201);

    expect(response.body).toEqual({
      message: 'User logged in successfully',
      userId: expect.any(String),
      email: 'test@example.com',
    });
  });

  it('POST /auth/login should return 401 if credentials are invalid', async () => {
    // Сначала регистрируем пользователя
    await request(app.getHttpServer())
      .post('/auth/register')
      .send({
        email: 'test@example.com',
        password: 'password123',
        name: 'Test User',
      })
      .expect(201);

    // Проверяем логин с неверным паролем
    const response = await request(app.getHttpServer())
      .post('/auth/login')
      .send({
        email: 'test@example.com',
        password: 'wrongpassword',
      })
      .expect(401);

    expect(response.body).toEqual({
      statusCode: 401,
      message: 'Invalid email or password',
      error: 'Unauthorized',
    });
  });
});
