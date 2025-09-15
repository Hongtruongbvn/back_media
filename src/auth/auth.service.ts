import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  BadRequestException,
  NotFoundException,
  InternalServerErrorException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { User, UserDocument } from './schemas/user.schema';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { MailerService } from '@nestjs-modules/mailer';
import { randomBytes, createHash } from 'crypto';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private jwtService: JwtService,
    private readonly mailerService: MailerService,
    private readonly configService: ConfigService,
  ) {}

  // --- Đăng ký ---
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

    // Mã hóa mật khẩu
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new this.userModel({
      username,
      email,
      password: hashedPassword,
      isEmailVerified: false,
    });

    // Lưu user, bắt lỗi duplicate key
    let result: UserDocument;
    try {
      result = await newUser.save();
    } catch (error: any) {
      // Mongo duplicate key
      if (error?.code === 11000) {
        // Tìm trường nào trùng (username / email)
        const key = Object.keys(error.keyValue || {})[0];
        const value = error.keyValue ? error.keyValue[key] : undefined;
        throw new ConflictException(
          `${key || 'Trường'} "${value}" đã tồn tại.`,
        );
      }
      throw new InternalServerErrorException('Đăng ký thất bại');
    }

    // Thử gửi email — nếu thất bại, KHÔNG rollback user; chỉ log và trả thông tin về frontend
    let mailInfo = { success: false, error: null };
    try {
      await this.sendVerificationEmail(result);
      mailInfo.success = true;
    } catch (err: any) {
      // Log lỗi (console để dễ debug trên cloud)
      console.error('Error sending verification email:', err);
      mailInfo.success = false;
      mailInfo.error = err?.message || String(err);
    }

    const { password: _, ...user } = result.toObject();
    return { user, mailInfo };
  }

  async sendVerificationEmail(user: UserDocument) {
    // Sinh token riêng cho verify (hết hạn nhanh, ví dụ 24h)
    const verificationToken = this.jwtService.sign(
      { sub: user._id.toString(), email: user.email },
      {
        expiresIn:
          this.configService.get<string>('VERIFY_TOKEN_EXPIRES_IN') || '1d',
      },
    );

    // Lấy frontend url từ env (fallback dùng url bạn gửi)
    const frontendUrl =
      this.configService.get<string>('FRONTEND_URL') ||
      'https://font-media.vercel.app';

    const verificationUrl = `${frontendUrl.replace(/\/$/, '')}/verify-email?token=${verificationToken}`;

    // Gửi mail
    const sendResult = await this.mailerService.sendMail({
      to: user.email,
      subject: 'Chào mừng! Vui lòng xác thực email của bạn',
      html: `<p>Xin chào ${user.username},</p>
             <p>Cảm ơn bạn đã đăng ký. Vui lòng bấm vào <a href="${verificationUrl}">đây</a> để xác thực tài khoản. Link có hiệu lực trong 24 giờ.</p>`,
    });

    return sendResult;
  }

  async verifyEmail(token: string): Promise<{ message: string }> {
    try {
      const payload: any = this.jwtService.verify(token);
      await this.userModel.updateOne(
        { _id: payload.sub },
        { isEmailVerified: true },
      );
      return { message: 'Xác thực email thành công!' };
    } catch (error) {
      throw new BadRequestException(
        'Token xác thực không hợp lệ hoặc đã hết hạn.',
      );
    }
  }

  // --- Đăng nhập ---
  async login(loginUserDto: LoginUserDto): Promise<{ accessToken: string }> {
    const { email, password } = loginUserDto;

    const user = await this.userModel.findOne({ email }).select('+password');
    if (!user) {
      throw new UnauthorizedException('Email hoặc mật khẩu không chính xác.');
    }

    const isPasswordMatched = await bcrypt.compare(password, user.password);
    if (!isPasswordMatched) {
      throw new UnauthorizedException('Email hoặc mật khẩu không chính xác.');
    }

    // 🚨 Check verify email
    if (!user.isEmailVerified) {
      throw new UnauthorizedException(
        'Tài khoản chưa được xác thực email. Vui lòng kiểm tra email hoặc yêu cầu gửi lại liên kết xác thực.',
      );
    }

    const payload = { sub: user._id, username: user.username };
    const accessToken = this.jwtService.sign(payload);

    return { accessToken };
  }

  async forgotPassword(email: string): Promise<{ message: string }> {
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new NotFoundException('Không tìm thấy người dùng với email này.');
    }

    const resetToken = randomBytes(32).toString('hex');
    user.passwordResetToken = createHash('sha256')
      .update(resetToken)
      .digest('hex');
    user.passwordResetExpires = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();

    const frontendUrl =
      this.configService.get<string>('FRONTEND_URL') ||
      'https://font-media.vercel.app';

    const resetUrl = `${frontendUrl.replace(/\/$/, '')}/reset-password/${resetToken}`;

    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Yêu cầu Đặt lại Mật khẩu',
      html: `<p>Bạn đã yêu cầu đặt lại mật khẩu. Vui lòng bấm vào <a href="${resetUrl}">đây</a> để tiếp tục.</p><p>Link này sẽ hết hạn sau 10 phút.</p>`,
    });

    return { message: 'Email đặt lại mật khẩu đã được gửi.' };
  }

  async resetPassword(
    token: string,
    newPassword: string,
  ): Promise<{ message: string }> {
    const hashedToken = createHash('sha256').update(token).digest('hex');

    const user = await this.userModel.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) {
      throw new BadRequestException('Token không hợp lệ hoặc đã hết hạn.');
    }

    const salt = await bcrypt.genSalt();
    user.password = await bcrypt.hash(newPassword, salt);
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    return { message: 'Đặt lại mật khẩu thành công.' };
  }
}
