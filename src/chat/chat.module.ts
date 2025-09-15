import { Module } from '@nestjs/common';
import { ChatService } from './chat.service';
import { ChatController } from './chat.controller';
import { ChatGateway } from './chat.gateway';
import { MongooseModule } from '@nestjs/mongoose';
import { Chatroom, ChatroomSchema } from './schemas/chatroom.schema';
import { Message, MessageSchema } from './schemas/message.schema';
import { AuthModule } from '../auth/auth.module';
import { User, UserSchema } from '../auth/schemas/user.schema';
import { ChatbotModule } from '../chatbot/chatbot.module';
import { BlockModule } from '../block/block.module'; 
import { PresenceModule } from 'src/presence/presence.module';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Chatroom.name, schema: ChatroomSchema },
      { name: Message.name, schema: MessageSchema },
      { name: User.name, schema: UserSchema }, // Cần để xác thực user
    ]),
    AuthModule,
    ChatbotModule,
    PresenceModule,
    BlockModule, // Thêm module chatbot để sử dụng dịch vụ chatbot
  ],
  providers: [ChatGateway, ChatService],
  controllers: [ChatController],
})
export class ChatModule {}
