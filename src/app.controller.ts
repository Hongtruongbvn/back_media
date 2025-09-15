import { Controller, Get, Request, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { JwtAuthGuard } from './auth/guards/jwt-auth.guard';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  @UseGuards(JwtAuthGuard) // Bảo vệ route này
  @Get('profile')
  getProfile(@Request() req) {
    // req.user chứa thông tin user từ JWT Strategy
    return { message: 'Đây là trang profile của bạn', user: req.user };
  }
}
