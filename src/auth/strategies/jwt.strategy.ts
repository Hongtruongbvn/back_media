import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument, AccountStatus } from '../schemas/user.schema';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    configService: ConfigService,
  ) {
    const jwtSecret = configService.get<string>('JWT_SECRET');
    if (!jwtSecret) {
      throw new Error('JWT_SECRET is not defined in configuration');
    }
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: jwtSecret,
    });
  }

  async validate(payload: { sub: string, username: string }): Promise<UserDocument> {
    const user = await this.userModel.findById(payload.sub);
    if (!user) {
      throw new UnauthorizedException('Người dùng không tồn tại.');
    }

    // --- KIỂM TRA TRẠNG THÁI TÀI KHOẢN ---
    if (user.accountStatus === AccountStatus.BANNED) {
        throw new UnauthorizedException('Tài khoản của bạn đã bị khóa vĩnh viễn.');
    }

    if (user.accountStatus === AccountStatus.SUSPENDED) {
        if (user.suspensionExpires && user.suspensionExpires > new Date()) {
            throw new UnauthorizedException(`Tài khoản của bạn đang bị tạm khóa cho đến ${user.suspensionExpires.toLocaleString()}.`);
        } else {
            // Nếu đã hết hạn khóa, tự động kích hoạt lại
            user.accountStatus = AccountStatus.ACTIVE;
            user.suspensionExpires = undefined;
            await user.save();
        }
    }

    return user;
  }
}