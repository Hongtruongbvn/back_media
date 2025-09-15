import { Injectable, Logger, InternalServerErrorException } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';
import { ModerationStatus } from '../posts/schemas/post.schema';

interface ModerationResult {
  status: ModerationStatus;
  reason?: string;
}

@Injectable()
export class ModerationService {
  private readonly apiKey: string;
  private readonly textApiUrl: string;
  private readonly logger = new Logger(ModerationService.name);
  // --- FIX: Thêm danh sách từ bị cấm (blocklist) ---
  private readonly blocklist: string[] = [
    'địt mẹ', 'dit me', 'đmm', 'dmm',
    'đéo', 'deo',
    'lồn', 'lon',
    'cặc', 'cac',
    'chó đẻ', 'cho de',
  ];

  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {
    const apiKey = this.configService.get<string>('GOOGLE_AI_API_KEY');
    if (!apiKey) {
      this.logger.error('Google AI API Key is not configured in .env file.');
      throw new Error('Google AI API Key is not configured.');
    }
    this.apiKey = apiKey;
    this.textApiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${this.apiKey}`;
  }

  async checkText(text: string): Promise<ModerationResult> {
    // --- FIX: Bước 1: Kiểm tra bằng blocklist thủ công ---
    const normalizedText = text.toLowerCase().trim();
    for (const blockedWord of this.blocklist) {
      if (normalizedText.includes(blockedWord)) {
        const reason = 'Nội dung chứa từ ngữ không được phép.';
        this.logger.warn(`Text moderation failed due to manual blocklist. Found: "${blockedWord}"`);
        return { status: ModerationStatus.REJECTED, reason };
      }
    }

    // --- Bước 2: Nếu vượt qua blocklist, kiểm tra bằng AI ---
    const payload = {
      contents: [{ parts: [{ text }] }],
      safetySettings: [
        { category: 'HARM_CATEGORY_HARASSMENT', threshold: 'BLOCK_LOW_AND_ABOVE' },
        { category: 'HARM_CATEGORY_HATE_SPEECH', threshold: 'BLOCK_LOW_AND_ABOVE' },
        { category: 'HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold: 'BLOCK_LOW_AND_ABOVE' },
        { category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_LOW_AND_ABOVE' },
      ],
    };

    try {
      const response = await firstValueFrom(this.httpService.post(this.textApiUrl, payload));
      
      if (response.data.promptFeedback?.blockReason) {
        const reason = `Nội dung bị chặn do: ${response.data.promptFeedback.blockReason}`;
        this.logger.warn(`Text moderation failed: ${reason}`);
        return { status: ModerationStatus.REJECTED, reason };
      }

      if (!response.data.candidates || response.data.candidates.length === 0) {
        this.logger.warn(`Text moderation blocked content without explicit reason.`);
        return { status: ModerationStatus.REJECTED, reason: 'Nội dung không phù hợp.' };
      }

      const candidate = response.data.candidates[0];
      if (candidate.finishReason === 'SAFETY') {
        this.logger.warn(`Text moderation blocked due to candidate finishReason: SAFETY.`);
        return { status: ModerationStatus.REJECTED, reason: 'Nội dung không phù hợp do cài đặt an toàn.' };
      }

      return { status: ModerationStatus.APPROVED };
    } catch (error) {
      this.logger.error('Error calling Gemini API for text moderation', error.response?.data || error.message);
      
      throw new InternalServerErrorException('Không thể kiểm duyệt nội dung vào lúc này. Vui lòng thử lại sau.');
    }
  }
}
