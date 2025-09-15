import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { MailerModule } from '@nestjs-modules/mailer';
import { MongooseModule } from '@nestjs/mongoose';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { ServeStaticModule } from '@nestjs/serve-static';       // 👈 NEW
import { join } from 'path';                                    // 👈 NEW

import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { PostsModule } from './posts/posts.module';
import { ChatModule } from './chat/chat.module';
import { NotificationsModule } from './notifications/notifications.module';
import { GroupsModule } from './groups/groups.module';
import { InterestsModule } from './interests/interests.module';
import { WebRTCModule } from './webrtc/webrtc.module';
import { RewardsModule } from './rewards/rewards.module';
import { ShopModule } from './shop/shop.module';
import { InventoryModule } from './inventory/inventory.module';
import { PaymentsModule } from './payments/payments.module';
import { GameActivityModule } from './game-activity/game-activity.module';
import { ModerationModule } from './moderation/moderation.module';
import { MediaProcessingModule } from './media-processing/media-processing.module';
import { ChatbotModule } from './chatbot/chatbot.module';
import { FriendsModule } from './friends/friends.module';
import { ReportsModule } from './reports/reports.module';
import { AdminModule } from './admin/admin.module';
import { StoriesModule } from './stories/stories.module';
import { LivestreamModule } from './livestream/livestream.module';
import { PresenceModule } from './presence/presence.module';
import { SettingsModule } from './settings/settings.module';
import { CoinPackagesModule } from './coin-packages/coin-packages.module';
import { SearchModule } from './search/search.module';
import { BlockModule } from './block/block.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env'],
    }),

    // 👇 Serve static cho thư mục uploads (ảnh nhóm, avatar…)
    ServeStaticModule.forRoot({
      rootPath: join(process.cwd(), 'uploads'),
      serveRoot: '/uploads', // => http://<API>/uploads/...
    }),

    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: config.get<string>('JWT_EXPIRES_IN'),
        },
      }),
    }),

    MailerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        transport: {
          host: config.get<string>('MAIL_HOST'),
          port: config.get<number>('MAIL_PORT'),
          secure: config.get<boolean>('MAIL_SECURE'),
          auth: {
            user: config.get<string>('MAIL_USER'),
            pass: config.get<string>('MAIL_PASS'),
          },
        },
        defaults: {
          from:
            config.get<string>('MAIL_FROM') ||
            '"No Reply" <no-reply@yourdomain.com>',
        },
        verify: false,
      }),
    }),

    EventEmitterModule.forRoot(),
    MongooseModule.forRoot(
      process.env.MONGO_URI ??
        (() => {
          throw new Error('MONGO_URI is not defined');
        })(),
    ),

    AuthModule,
    UsersModule,
    PostsModule,
    ChatModule,
    NotificationsModule,
    GroupsModule,
    InterestsModule,
    WebRTCModule,
    RewardsModule,
    ShopModule,
    InventoryModule,
    PaymentsModule,
    GameActivityModule,
    ModerationModule,
    MediaProcessingModule,
    ChatbotModule,
    FriendsModule,
    ReportsModule,
    AdminModule,
    StoriesModule,
    LivestreamModule,
    PresenceModule,
    SettingsModule,
    CoinPackagesModule,
    SearchModule,
    BlockModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
