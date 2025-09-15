import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module';
import { getModelToken } from '@nestjs/mongoose';
import { User } from '../auth/schemas/user.schema';
import * as bcrypt from 'bcrypt';
import { Model } from 'mongoose';

async function bootstrap() {
  // Khởi tạo môi trường NestJS để có thể dùng các model
  const app = await NestFactory.createApplicationContext(AppModule);
  const userModel = app.get<Model<User>>(getModelToken(User.name));

  console.log('Bắt đầu tạo người dùng chatbot...');

  const chatbotEmail = 'chatbot@grandproject.com';
  const existingBot = await userModel.findOne({ email: chatbotEmail });

  // Kiểm tra xem bot đã tồn tại chưa
  if (existingBot) {
    console.log('Người dùng chatbot đã tồn tại.');
    console.log('Chatbot User ID:', existingBot._id.toString());
    await app.close();
    return;
  }

  // Mã hóa mật khẩu cho bot
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash('a_very_strong_password_for_bot', salt);

  const chatbot = new userModel({
    username: 'ai_assistant',
    email: chatbotEmail,
    password: hashedPassword,
    avatar: 'https://img.freepik.com/free-vector/chatbot-chat-message-vectorart_78370-4104.jpg?semt=ais_items_boosted&w=740',
    bio: 'Tôi là trợ lý ảo, sẵn sàng giúp đỡ bạn!',
  });

  const savedBot = await chatbot.save();
  console.log('Tạo người dùng chatbot thành công!');
  console.log('Chatbot User ID:', savedBot._id.toString());

  await app.close();
}

bootstrap();