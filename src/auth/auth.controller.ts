import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  Param,
  Get,
  Query,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { UseGuards } from '@nestjs/common'; // Thêm Get và UseGuards vào import
import { JwtAuthGuard } from './guards/jwt-auth.guard'; // Import JwtAuthGuard
import { GetUser } from './decorators/get-user.decorator'; // Import GetUser decorator
import { UserDocument } from './schemas/user.schema'; // Import UserDocument

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() createUserDto: CreateUserDto) {
    const user = await this.authService.register(createUserDto);
    return { message: 'Đăng ký thành công!', user };
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() loginUserDto: LoginUserDto) {
    return this.authService.login(loginUserDto);
  }

  @Post('forgot-password')
  forgotPassword(@Body('email') email: string) {
    return this.authService.forgotPassword(email);
  }

  @Post('reset-password/:token')
  resetPassword(
    @Param('token') token: string,
    @Body('password') password: string,
  ) {
    return this.authService.resetPassword(token, password);
  }

  @Get('verify-email')
  verifyEmail(@Query('token') token: string) {
    return this.authService.verifyEmail(token);
  }

  @UseGuards(JwtAuthGuard) // Bảo vệ route này, yêu cầu phải có token hợp lệ
  @Get('me')
  getMe(@GetUser() user: UserDocument) {
    // Decorator @GetUser sẽ lấy user đã được xác thực từ token
    // Trả về thông tin user (không bao gồm mật khẩu)
    const { password, ...result } = user.toObject();
    return result;
  }
}
