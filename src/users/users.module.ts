// apps/api/src/users/users.module.ts
import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from '../auth/schemas/user.schema';
import { AuthModule } from '../auth/auth.module';
import { NotificationsModule } from '../notifications/notifications.module';

@Module({
  imports: [
    // Cho phép module này inject UserModel
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
    // Import AuthModule để có thể dùng JwtAuthGuard
    AuthModule,
    NotificationsModule, // Import NotificationsModule để gửi thông báo khi có người theo dõi
  ],
  controllers: [UsersController],
  providers: [UsersService],
  exports: [UsersService],
})
export class UsersModule {}
