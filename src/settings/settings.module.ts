import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { SettingsService } from './settings.service';
import { AdminSettingsController } from './admin-settings.controller';
import { Settings, SettingsSchema } from './schemas/settings.schema';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Settings.name, schema: SettingsSchema }]),
    AuthModule,
  ],
  controllers: [AdminSettingsController],
  providers: [SettingsService],
})
export class SettingsModule {}
