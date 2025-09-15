import { Injectable, Logger } from '@nestjs/common';
import { MailerSend, EmailParams, Sender, Recipient } from 'mailersend';

@Injectable()
export class MailerService {
  private readonly logger = new Logger(MailerService.name);
  private readonly mailersend: MailerSend;
  private readonly from: Sender;

  constructor() {
    this.mailersend = new MailerSend({
      apiKey: process.env.MAILERSEND_API_KEY || '',
    });

    // địa chỉ gửi mặc định
    this.from = new Sender('truongtruongbvn@gmail.com', 'No Reply');
  }

  async sendMail(to: string, subject: string, html: string) {
    try {
      const recipients = [new Recipient(to, to)];

      const emailParams = new EmailParams()
        .setFrom(this.from)
        .setTo(recipients)
        .setSubject(subject)
        .setHtml(html);

      await this.mailersend.email.send(emailParams);
      this.logger.log(`Email sent successfully to ${to}`);
    } catch (error: any) {
      this.logger.error(`Error sending email: ${error.message}`, error.stack);
      throw error;
    }
  }
}
