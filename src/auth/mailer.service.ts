import { Injectable, Logger } from '@nestjs/common';
import axios from 'axios';

@Injectable()
export class MailerService {
  private readonly logger = new Logger(MailerService.name);
  private readonly apiKey = process.env.BREVO_API_KEY || 'your_brevo_api_key';
  private readonly senderEmail =
    process.env.MAIL_FROM || 'truongtruongbvn@gmail.com';
  private readonly senderName = 'GrandProject';

  async sendMail(to: string, subject: string, html: string) {
    try {
      const response = await axios.post(
        'https://api.brevo.com/v3/smtp/email',
        {
          sender: {
            name: this.senderName,
            email: this.senderEmail,
          },
          to: [{ email: to }],
          subject,
          htmlContent: html,
        },
        {
          headers: {
            'api-key': this.apiKey,
            'Content-Type': 'application/json',
          },
        },
      );

      this.logger.log(
        `✅ Email sent to ${to}, Message ID: ${response.data.messageId}`,
      );
      return { success: true, messageId: response.data.messageId };
    } catch (error: any) {
      this.logger.error(
        `❌ Error sending email: ${error.message}`,
        error.stack,
      );
      throw new Error(`Error sending email: ${error.message}`);
    }
  }
}
