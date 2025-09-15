import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  Param,
  Get,
  Query,
  UseGuards,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { GetUser } from './decorators/get-user.decorator';
import { UserDocument } from './schemas/user.schema';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() createUserDto: CreateUserDto) {
    const { user, mailInfo } = await this.authService.register(createUserDto);
    // Trả lại thông tin user (không có mật khẩu) và trạng thái gửi mail
    return { message: 'Đăng ký thành công!', user, mailInfo };
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

  @UseGuards(JwtAuthGuard)
  @Get('me')
  getMe(@GetUser() user: UserDocument) {
    const { password, ...result } = user.toObject();
    return result;
  }
  @Post('resend-verification')
  async resendVerification(@Body() body: { email?: string; token?: string }) {
    let user: UserDocument | null = null;

    if (body.email) {
      user = await this.authService.findUserByEmail(body.email);
    } else if (body.token) {
      user = await this.authService.findUserByToken(body.token);
    } else {
      throw new BadRequestException('Cần cung cấp email hoặc token.');
    }

    if (!user) {
      throw new NotFoundException('Không tìm thấy người dùng.');
    }

    return this.authService.resendVerificationEmail(user);
  }
}
