import { Injectable, Logger } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailerService {
  private readonly logger = new Logger(MailerService.name);
  private readonly transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587, // hoặc 465 nếu muốn SSL
      secure: false, // true cho 465, false cho 587
      auth: {
        user: 'truongtruongbvn@gmail.com',
        pass: 'ugai ffun mhkt zpfh', // Gmail App Password
      },
    });
  }

  async sendMail(to: string, subject: string, html: string) {
    try {
      const info = await this.transporter.sendMail({
        from: `"Media App" <truongtruongbvn@gmail.com>`, // Tên hiển thị + email gửi
        to,
        subject,
        html,
      });

      this.logger.log(`Email sent to ${to}: ${info.messageId}`);
      return { success: true, messageId: info.messageId };
    } catch (error: any) {
      this.logger.error(`Error sending email: ${error.message}`, error.stack);
      throw error;
    }
  }
}
