import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  BadRequestException,
  NotFoundException,
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

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private jwtService: JwtService,
    private readonly mailerService: MailerService,
  ) {}

  // --- Đăng ký ---
  async register(
    createUserDto: CreateUserDto,
  ): Promise<Omit<User, 'password'>> {
    // ... logic kiểm tra user tồn tại, mã hóa mật khẩu ...
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
      isEmailVerified: false, // Mặc định là chưa xác thực
    });

    const result = await newUser.save();

    // Gửi email xác thực
    await this.sendVerificationEmail(result);

    const { password: _, ...user } = result.toObject();
    return user;
  }

  async sendVerificationEmail(user: UserDocument) {
    // Tạo một token đơn giản, có thể dùng JWT hoặc crypto
    const verificationToken = this.jwtService.sign({
      sub: user._id,
      email: user.email,
    });
    const verificationUrl = `http://localhost:5173/verify-email?token=${verificationToken}`;

    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Chào mừng! Vui lòng xác thực email của bạn',
      html: `<p>Cảm ơn bạn đã đăng ký. Vui lòng bấm vào <a href="${verificationUrl}">đây</a> để xác thực tài khoản.</p>`,
    });
  }

  async verifyEmail(token: string): Promise<{ message: string }> {
    try {
      const payload = this.jwtService.verify(token);
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
  async login(
    loginUserDto: LoginUserDto,
  ): Promise<{ accessToken: string }> {
    const { email, password } = loginUserDto;

    // SỬA LỖI: Thêm .select('+password') để lấy cả trường password đã bị ẩn
    const user = await this.userModel.findOne({ email }).select('+password');

    if (!user) {
      throw new UnauthorizedException('Email hoặc mật khẩu không chính xác.');
    }

    // Bây giờ user.password đã có giá trị
    const isPasswordMatched = await bcrypt.compare(password, user.password);

    if (!isPasswordMatched) {
      throw new UnauthorizedException('Email hoặc mật khẩu không chính xác.');
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

    // 1. Tạo token
    const resetToken = randomBytes(32).toString('hex');
    user.passwordResetToken = createHash('sha256')
      .update(resetToken)
      .digest('hex');
    user.passwordResetExpires = new Date(Date.now() + 10 * 60 * 1000); // Hết hạn sau 10 phút
    await user.save();

    // 2. Gửi email
    // URL này sẽ trỏ đến trang đặt lại mật khẩu trên Frontend của bạn
    const resetUrl = `http://localhost:5173/reset-password/${resetToken}`;

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

    // Cập nhật mật khẩu mới đã được mã hóa
    const salt = await bcrypt.genSalt();
    user.password = await bcrypt.hash(newPassword, salt);
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    return { message: 'Đặt lại mật khẩu thành công.' };
  }
  
}
