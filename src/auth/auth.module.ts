import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { MongooseModule } from '@nestjs/mongoose';
import { MailerModule } from '@nestjs-modules/mailer';

import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './strategies/jwt.strategy';
import { User, UserSchema } from './schemas/user.schema';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';
import * as path from 'path';

@Module({
  imports: [
    ConfigModule,
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_SECRET') || 'default_jwt_secret',
        signOptions: {
          expiresIn: config.get<string>('JWT_EXPIRES_IN') || '7d',
        },
      }),
    }),
    MailerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (config: ConfigService) => {
        const host = config.get<string>('EMAIL_HOST');
        const port = Number(config.get<string>('EMAIL_PORT') || 465);
        const secure =
          config.get<string>('EMAIL_SECURE') === 'true' ? true : port === 465;
        return {
          transport: {
            host,
            port,
            secure,
            auth: {
              user: config.get<string>('EMAIL_USER'),
              pass: config.get<string>('EMAIL_PASS'),
            },
          },
          defaults: {
            from:
              config.get<string>('EMAIL_FROM') ||
              '"No Reply" <no-reply@example.com>',
          },
          // nếu muốn template dùng Handlebars:
          preview: config.get<string>('EMAIL_PREVIEW') === 'true',
          template: {
            dir: path.resolve(__dirname, '..', 'templates', 'emails'),
            adapter: new HandlebarsAdapter(),
            options: { strict: true },
          },
        };
      },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy],
  exports: [PassportModule, JwtModule, JwtStrategy],
})
export class AuthModule {}
