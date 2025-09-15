import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  BadRequestException,
  NotFoundException,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { randomBytes, createHash } from 'crypto';
import { User, UserDocument } from './schemas/user.schema';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { MailerService } from './mailer.service';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private jwtService: JwtService,
    private readonly mailerService: MailerService,
  ) {}

  async register(
    createUserDto: CreateUserDto,
  ): Promise<{ user: any; mailInfo?: any }> {
    const { username, email, password } = createUserDto;

    const reservedUsernames = [
      'admin',
      'moderator',
      'support',
      'root',
      'administrator',
    ];
    if (reservedUsernames.includes(username.toLowerCase())) {
      throw new ConflictException(
        'Tên người dùng này không được phép sử dụng.',
      );
    }

    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new this.userModel({
      username,
      email,
      password: hashedPassword,
      isEmailVerified: false,
    });

    let result: UserDocument;
    try {
      result = await newUser.save();
    } catch (error: any) {
      if (error?.code === 11000) {
        const key = Object.keys(error.keyValue || {})[0];
        const value = error.keyValue ? error.keyValue[key] : undefined;
        throw new ConflictException(
          `${key || 'Trường'} "${value}" đã tồn tại.`,
        );
      }
      throw new InternalServerErrorException('Đăng ký thất bại');
    }

    let mailInfo = { success: false, error: null };
    try {
      await this.sendVerificationEmailWithRetry(result, 3);
      mailInfo.success = true;
    } catch (err: any) {
      this.logger.error('Error sending verification email after retries:', err);
      mailInfo.success = false;
      mailInfo.error = err.message || String(err);
    }

    const { password: _, ...user } = result.toObject();
    return { user, mailInfo };
  }

  private async sendVerificationEmailWithRetry(
    user: UserDocument,
    maxRetries = 3,
  ): Promise<void> {
    let lastError: any;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        await this.sendVerificationEmail(user);
        this.logger.log(
          `Verification email sent successfully on attempt ${attempt}`,
        );
        return;
      } catch (error) {
        lastError = error;
        this.logger.warn(`Attempt ${attempt} failed: ${error.message}`);
        if (attempt < maxRetries) {
          await new Promise((r) => setTimeout(r, 1000 * attempt));
        }
      }
    }
    throw lastError;
  }

  async sendVerificationEmail(user: UserDocument) {
    const token = this.jwtService.sign(
      { sub: user._id.toString(), email: user.email },
      { expiresIn: process.env.VERIFY_TOKEN_EXPIRES_IN || '1d' },
    );

    const frontendUrl =
      process.env.FRONTEND_URL || 'https://www.miproject.online';
    const verificationUrl = `${frontendUrl.replace(/\/$/, '')}/api/auth/verify-email?token=${token}`;

    return Promise.race([
      this.mailerService.sendMail(
        user.email,
        'Chào mừng! Vui lòng xác thực email của bạn',
        `<p>Xin chào ${user.username},</p>
         <p>Cảm ơn bạn đã đăng ký. Nhấn vào <a href="${verificationUrl}">đây</a> để xác thực tài khoản (hiệu lực 24h).</p>`,
      ),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Email sending timeout')), 15000),
      ),
    ]);
  }
  async verifyEmail(token: string): Promise<{ message: string }> {
    try {
      // Verify the token
      const payload = this.jwtService.verify(token, {
        secret:
          process.env.JWT_SECRET ||
          'kElQAyEpvvFYU4jGJpkSwhgIwMyvrBcCHMhxPUTWeuPUOnfWCq',
      });

      // Find user by ID from token
      const user = await this.userModel.findById(payload.sub);
      if (!user) {
        throw new NotFoundException('Người dùng không tồn tại');
      }

      // Check if email already verified
      if (user.isEmailVerified) {
        return { message: 'Email đã được xác thực trước đó' };
      }

      // Verify that the email in token matches user's email
      if (payload.email !== user.email) {
        throw new BadRequestException('Token không khớp với email người dùng');
      }

      // Update user as verified
      user.isEmailVerified = true;
      await user.save();

      return { message: 'Email đã được xác thực thành công' };
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new BadRequestException('Token đã hết hạn');
      }
      if (error.name === 'JsonWebTokenError') {
        throw new BadRequestException('Token không hợp lệ');
      }
      if (
        error.name === 'NotFoundException' ||
        error.name === 'BadRequestException'
      ) {
        throw error;
      }
      throw new InternalServerErrorException('Lỗi xác thực email');
    }
  }

  async login(loginUserDto: LoginUserDto): Promise<{ accessToken: string }> {
    const { email, password } = loginUserDto;
    const user = await this.userModel.findOne({ email }).select('+password');
    if (!user)
      throw new UnauthorizedException('Email hoặc mật khẩu không chính xác.');

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      throw new UnauthorizedException('Email hoặc mật khẩu không chính xác.');

    if (!user.isEmailVerified) {
      throw new UnauthorizedException(
        'Tài khoản chưa xác thực email. Kiểm tra hộp thư hoặc yêu cầu gửi lại liên kết.',
      );
    }

    const payload = { sub: user._id, username: user.username };
    return { accessToken: this.jwtService.sign(payload) };
  }

  async forgotPassword(email: string): Promise<{ message: string }> {
    const user = await this.userModel.findOne({ email });
    if (!user)
      throw new NotFoundException('Không tìm thấy người dùng với email này.');

    const resetToken = randomBytes(32).toString('hex');
    user.passwordResetToken = createHash('sha256')
      .update(resetToken)
      .digest('hex');
    user.passwordResetExpires = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();

    const frontendUrl =
      process.env.FRONTEND_URL || 'https://www.miproject.online';
    const resetUrl = `${frontendUrl.replace(/\/$/, '')}/api/auth/reset-password/${resetToken}`;

    await this.mailerService.sendMail(
      user.email,
      'Yêu cầu Đặt lại Mật khẩu',
      `<p>Bạn đã yêu cầu đặt lại mật khẩu. Nhấn vào <a href="${resetUrl}">đây</a> để tiếp tục. Link hết hạn sau 10 phút.</p>`,
    );

    return { message: 'Email đặt lại mật khẩu đã được gửi.' };
  }

  async resetPassword(
    token: string,
    newPassword: string,
  ): Promise<{ message: string }> {
    const hashed = createHash('sha256').update(token).digest('hex');
    const user = await this.userModel.findOne({
      passwordResetToken: hashed,
      passwordResetExpires: { $gt: Date.now() },
    });
    if (!user)
      throw new BadRequestException('Token không hợp lệ hoặc đã hết hạn.');

    const salt = await bcrypt.genSalt();
    user.password = await bcrypt.hash(newPassword, salt);
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    return { message: 'Đặt lại mật khẩu thành công.' };
  }

  async findUserByEmail(email: string): Promise<UserDocument | null> {
    return this.userModel.findOne({ email });
  }

  async resendVerificationEmail(user: UserDocument) {
    try {
      await this.sendVerificationEmailWithRetry(user, 3);
      return { success: true };
    } catch (err: any) {
      this.logger.error('Error resending verification email:', err);
      return { success: false, error: err?.message || String(err) };
    }
  }
  async findUserByToken(token: string): Promise<UserDocument | null> {
    try {
      const payload: any = this.jwtService.verify(token);
      return this.userModel.findById(payload.sub);
    } catch (err) {
      this.logger.error('Không thể giải mã token:', err);
      return null;
    }
  }
}
