import { ConsoleLogger } from '@nestjs/common';

export class CustomLogger extends ConsoleLogger {
  error(message: any, trace?: string, context?: string) {
    // Hạ thành LOG nếu là thông báo transporter ready
    if (typeof message === 'string' && message.includes('Transporter is ready')) {
      return super.log(message, context);
    }
    // Các lỗi khác vẫn là error
    return super.error(message, trace, context);
  }
}
