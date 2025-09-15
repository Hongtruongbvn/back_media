import { Module } from '@nestjs/common';
import { ChatbotService } from './chatbot.service';
import { HttpModule } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { ChatbotController } from './chatbot.controller';

@Module({
  imports: [HttpModule],
  providers: [ChatbotService, ConfigService],
  controllers:[ChatbotController],
  exports: [ChatbotService],
})
export class ChatbotModule {}