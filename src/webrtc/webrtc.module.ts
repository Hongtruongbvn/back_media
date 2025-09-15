import { Module } from '@nestjs/common';
import { WebRTCGateway } from './webrtc.gateway';
import { AuthModule } from '../auth/auth.module';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from '../auth/schemas/user.schema';

@Module({
  imports: [
    AuthModule,
    // Chúng ta cần UserModel để lấy thông tin user từ token
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
  ],
  providers: [WebRTCGateway, JwtService, ConfigService],
  exports: [WebRTCGateway],
})
export class WebRTCModule {}