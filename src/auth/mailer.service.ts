import { Injectable, Logger } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailerService {
  private readonly logger = new Logger(MailerService.name);
  private readonly transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: 'smtp-relay.brevo.com',
      port: 587,
      secure: false,
      auth: {
        user: process.env.BREVO_SMTP_USER || '97089e001@smtp-brevo.com',
        pass: process.env.BREVO_SMTP_PASS || 'Q5OxAYHBWKsNFgEq',
      },
      connectionTimeout: 15000,
      greetingTimeout: 15000,
      socketTimeout: 15000,
    });
  }

  async sendMail(to: string, subject: string, html: string) {
    try {
      const info = await this.transporter.sendMail({
        from: `"No Reply" <${process.env.BREVO_SMTP_USER}>`,
        to,
        subject,
        html,
      });

      this.logger.log(`✅ Email sent to ${to}, ID: ${info.messageId}`);
      return { success: true, messageId: info.messageId };
    } catch (error: any) {
      this.logger.error(
        `❌ Error sending email: ${error.message}`,
        error.stack,
      );
      throw new Error(`Error sending email: ${error.message}`);
    }
  }
}
