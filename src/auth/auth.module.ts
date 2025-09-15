import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { MongooseModule } from '@nestjs/mongoose';
import { MailerModule } from '@nestjs-modules/mailer';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';
import * as path from 'path';

import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './strategies/jwt.strategy';
import { User, UserSchema } from './schemas/user.schema';

@Module({
  imports: [
    ConfigModule.forRoot(),
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({
      secret:
        process.env.JWT_SECRET ||
        'AZmewzIy6Tc1K8tkGJlfiQ8U3bUEUos6vSQ6ntxzdwLFecRlwD',
      signOptions: { expiresIn: process.env.JWT_EXPIRES_IN || '7d' },
    }),
    MailerModule.forRoot({
      transport: {
        host: process.env.SMTP_HOST || 'smtp.gmail.com',
        port: parseInt(process.env.SMTP_PORT || '465', 10),
        secure: true, // Gmail với port 465 bắt buộc secure
        auth: {
          user: process.env.SMTP_USER || 'truongtruongbvn@gmail.com',
          pass: process.env.SMTP_PASS || 'ugai ffun mhkt zpfh', // App password của Gmail
        },
        connectionTimeout: 15000,
        greetingTimeout: 15000,
        socketTimeout: 15000,
      },
      defaults: {
        from:
          process.env.SMTP_FROM ||
          `"No Reply" <${process.env.SMTP_USER || 'truongtruongbvn@gmail.com'}>`,
      },
      preview:
        process.env.NODE_ENV !== 'production' &&
        process.env.EMAIL_PREVIEW === 'true',
      template: {
        dir: path.join(__dirname, 'templates'),
        adapter: new HandlebarsAdapter(),
        options: { strict: true },
      },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy],
  exports: [PassportModule, JwtModule, JwtStrategy],
})
export class AuthModule {}
