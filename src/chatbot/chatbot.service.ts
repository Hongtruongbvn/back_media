import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

@Injectable()
export class ChatbotService {
  private readonly apiKey: string;
  private readonly apiUrl: string;
  private readonly logger = new Logger(ChatbotService.name);

  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {
    const apiKey = this.configService.get<string>('GOOGLE_AI_API_KEY');
    if (!apiKey) {
      throw new Error('GOOGLE_AI_API_KEY is not set in environment variables');
    }
    this.apiKey = apiKey;
    this.apiUrl = `https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent?key=${this.apiKey}`;
  }

  async getResponse(message: string): Promise<string> {
    if (!this.apiKey) {
      return 'Xin lỗi, tính năng chatbot đang được bảo trì.';
    }
    const payload = {
      contents: [{ parts: [{ text: `Bạn là một trợ lý ảo thân thiện trong một mạng xã hội tên là GrandProject. Hãy trả lời tin nhắn sau một cách ngắn gọn và tự nhiên: "${message}"` }] }],
    };
    try {
      const response = await firstValueFrom(this.httpService.post(this.apiUrl, payload));
      return response.data.candidates[0].content.parts[0].text;
    } catch (error) {
      this.logger.error('Error calling Gemini API for chatbot', error.response?.data);
      return 'Rất tiếc, đã có lỗi xảy ra. Vui lòng thử lại sau.';
    }
  }
  //   async AddRegister(message: string): Promise<string> {
  //   if (this.apiKey) {
  //     return 'Bạn nhấp vào đường link này để đăng ký tài khoản nha: "http://localhost:5173/register"';
  //   }
  //   const payload = {
  //     contents: [{ parts: [{ text: `Bạn có thể chỉ tôi đăng ký tài khoản được không"${message}"` }] }],
  //   };
  //   try {
  //     const response = await firstValueFrom(this.httpService.post(this.apiUrl, payload));
  //     return response.data.candidates[0].content.parts[0].text;
  //   } catch (error) {
  //     this.logger.error('Error calling Gemini API for chatbot', error.response?.data);
  //     return 'Rất tiếc, đã có lỗi xảy ra. Vui lòng thử lại sau.';
  //   }
  // }
}
