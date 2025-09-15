// File: apps/api/src/livestream/livestream.controller.ts (Cập nhật)
import { Controller, Post, Delete, Get, UseGuards, Body } from '@nestjs/common';
import { LivestreamService } from './livestream.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';
import { UserDocument } from '../auth/schemas/user.schema';
import { PremiumGuard } from '../auth/guards/premium.guard';
import { IsEnum } from 'class-validator';

// Tạo DTO để xác thực dữ liệu đầu vào cho stream chất lượng cao
class StartHdLivestreamDto {
    @IsEnum(['1080p', '1440p'])
    quality: '1080p' | '1440p';
}

@UseGuards(JwtAuthGuard)
@Controller('livestreams')
export class LivestreamController {
  constructor(private readonly livestreamService: LivestreamService) {}

  /**
   * Endpoint cho người dùng FREE. Chất lượng mặc định là 720p.
   */
  @Post('start')
  startLivestream(@GetUser() user: UserDocument) {
    // Gọi hàm với 2 tham số đã được sửa lỗi
    return this.livestreamService.startStream(user, '720p');
  }

  /**
   * Endpoint được bảo vệ, chỉ dành cho người dùng PREMIUM.
   */
  @Post('start-hd')
  @UseGuards(PremiumGuard)
  startHdLivestream(
    @GetUser() user: UserDocument,
    @Body() startHdLivestreamDto: StartHdLivestreamDto
  ) {
    // Gọi hàm với 2 tham số đã được sửa lỗi
    return this.livestreamService.startStream(user, startHdLivestreamDto.quality);
  }

  @Delete('end')
  endLivestream(@GetUser() user: UserDocument) {
    // SỬA LỖI: Truyền vào user.id (string) thay vì cả object user
    return this.livestreamService.endStream(user.id);
  }

  @Get('active')
  getActiveLivestreams() {
    return this.livestreamService.getActiveStreams();
  }
}