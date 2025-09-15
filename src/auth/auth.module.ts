import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { MongooseModule } from '@nestjs/mongoose';

import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './strategies/jwt.strategy';
import { User, UserSchema } from './schemas/user.schema';
import { MailerService } from './mailer.service';

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
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, MailerService],
  exports: [PassportModule, JwtModule, JwtStrategy],
})
export class AuthModule {}
