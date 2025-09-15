import { Module } from '@nestjs/common';
import { GameActivityService } from './game-activity.service';
import { GameActivityController } from './game-activity.controller';
import { HttpModule } from '@nestjs/axios';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from '../auth/schemas/user.schema';
import { AuthModule } from '../auth/auth.module';
import { NotificationsModule } from '../notifications/notifications.module';
import { PresenceModule } from '../presence/presence.module';

@Module({
  imports: [
    HttpModule,
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
    AuthModule,
    NotificationsModule, // Cần để gửi thông báo mời
    PresenceModule,      // Cần để kiểm tra trạng thái online
  ],
  controllers: [GameActivityController],
  providers: [GameActivityService],
})
export class GameActivityModule {}