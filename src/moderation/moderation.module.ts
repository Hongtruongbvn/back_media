import { Module } from '@nestjs/common';
import { ModerationService } from './moderation.service';
import { HttpModule } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';

@Module({
  imports: [HttpModule],
  providers: [ModerationService, ConfigService],
  exports: [ModerationService],
})
export class ModerationModule {}