import {
  Injectable,
  NotFoundException,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { User, UserDocument } from '../auth/schemas/user.schema';
import { UpdateUserDto } from './dto/update-user.dto';
import { NotificationsService } from '../notifications/notifications.service';
import { NotificationType } from '../notifications/schemas/notification.schema';
import * as path from 'path';
import * as fs from 'fs';

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private notificationsService: NotificationsService,
  ) {}

  // ===== PUBLIC: theo _id (cho FE fallback) =====
  async findPublicById(id: string | Types.ObjectId): Promise<UserDocument> {
    const idStr = String(id);
    if (!Types.ObjectId.isValid(idStr)) {
      throw new NotFoundException(`Không tìm thấy người dùng với id=${idStr}`);
    }

    const user = await this.userModel
      .findById(idStr)
      .select('-password -email')
      .populate({ path: 'equippedAvatarFrame', select: 'assetUrl type' })
      .exec();

    if (!user) {
      throw new NotFoundException(`Không tìm thấy người dùng với id=${idStr}`);
    }
    return user;
  }

  // ===== PUBLIC: nhận cả username hoặc ObjectId =====
  async findByUsernameOrId(param: string): Promise<UserDocument> {
    const isId = Types.ObjectId.isValid(param);
    const query = isId ? this.userModel.findById(param) : this.userModel.findOne({ username: param });

    const user = await query
      .select('-password -email')
      .populate({ path: 'equippedAvatarFrame', select: 'assetUrl type' })
      .exec();

    if (!user) {
      throw new NotFoundException(
        isId
          ? `Không tìm thấy người dùng với id=${param}`
          : `Không tìm thấy người dùng ${param}`,
      );
    }
    return user;
  }

  // (Giữ lại bản cũ để ai gọi trực tiếp theo username vẫn dùng được nội bộ)
  async findByUsername(username: string): Promise<UserDocument> {
    return this.findByUsernameOrId(username);
  }

  // ===== MUTATIONS & OTHERS =====
  async updateProfile(
    userId: string | Types.ObjectId,
    updateUserDto: UpdateUserDto,
  ): Promise<UserDocument> {
    const updated = await this.userModel
      .findByIdAndUpdate(userId, updateUserDto, { new: true })
      .select('-password')
      .exec();

    if (!updated) {
      throw new NotFoundException('Không tìm thấy người dùng');
    }
    return updated;
  }

  async updateAvatar(
    userId: string | Types.ObjectId,
    avatarPath: string,
  ): Promise<UserDocument> {
    const updated = await this.userModel
      .findByIdAndUpdate(userId, { avatar: avatarPath }, { new: true })
      .select('-password')
      .exec();

    if (!updated) {
      throw new NotFoundException(
        'Không tìm thấy người dùng khi cập nhật avatar',
      );
    }
    return updated;
  }

  async updateCover(
    userId: string | Types.ObjectId,
    coverPath: string,
  ): Promise<UserDocument> {
    const updated = await this.userModel
      .findByIdAndUpdate(userId, { coverImage: coverPath }, { new: true })
      .select('-password')
      .exec();

    if (!updated) {
      throw new NotFoundException(
        'Không tìm thấy người dùng khi cập nhật cover',
      );
    }
    return updated;
  }

  async followUser(
    currentUserId: string | Types.ObjectId,
    userIdToFollow: string,
  ) {
    if (currentUserId.toString() === userIdToFollow) {
      throw new Error('Bạn không thể tự theo dõi chính mình.');
    }
    await this.userModel.findByIdAndUpdate(currentUserId, {
      $addToSet: { following: userIdToFollow },
    });
    await this.userModel.findByIdAndUpdate(userIdToFollow, {
      $addToSet: { followers: currentUserId },
    });
    const userToFollowDoc = await this.userModel.findById(userIdToFollow);
    const currentUserDoc = await this.userModel.findById(currentUserId);
    if (!userToFollowDoc || !currentUserDoc) {
      throw new NotFoundException(
        'Không tìm thấy người dùng để tạo thông báo.',
      );
    }
    await this.receiveXP(
      2,
      'follow',
      currentUserId.toString(),
      userIdToFollow.toString(),
    );
    await this.notificationsService.createNotification(
      userToFollowDoc,
      currentUserDoc,
      NotificationType.NEW_FOLLOWER,
      `/profile/${currentUserDoc.username}`,
    );
    return { message: 'Theo dõi thành công.' };
  }

  async unfollowUser(
    currentUserId: string | Types.ObjectId,
    userIdToUnfollow: string,
  ) {
    await this.userModel.findByIdAndUpdate(currentUserId, {
      $pull: { following: userIdToUnfollow },
    });
    await this.userModel.findByIdAndUpdate(userIdToUnfollow, {
      $pull: { followers: currentUserId },
    });
    return { message: 'Bỏ theo dõi thành công.' };
  }

  async updateUserInterests(
    userId: string,
    interestIds: string[],
  ): Promise<UserDocument> {
    const updated = await this.userModel
      .findByIdAndUpdate(
        userId,
        { $set: { interests: interestIds, hasSelectedInterests: true } },
        { new: true },
      )
      .populate('interests')
      .exec();

    if (!updated) {
      throw new NotFoundException('Không tìm thấy người dùng');
    }
    return updated;
  }

  async receiveXP(
    xp: number,
    kind: string,
    userId: string,
    follow?: string,
  ): Promise<void> {
    const user = await this.userModel.findById(userId);
    if (!user) {
      this.logger.warn(`User with ID ${userId} not found.`);
      return;
    }
    if (kind === 'follow') {
      await this.handleUserFollowed(userId);
    }
    if (user.xp_per_day >= 250) {
      await this.notificationsService.createNotification(
        user,
        user,
        NotificationType.NEW_NOTIFICATION,
        null,
      );
      this.logger.log(`User ${user.username} reached daily XP limit.`);
      return;
    }
    const allowedXP = Math.max(0, 250 - user.xp_per_day);
    xp = Math.min(xp, allowedXP);
    user.xp_per_day += xp;
    user.xp += xp;
    await user.save();
  }

  async handleUserFollowed(followedUserId: string): Promise<void> {
    const user = await this.userModel.findById(followedUserId);
    if (!user) {
      this.logger.warn(`User with ID ${followedUserId} not found.`);
      return;
    }
    const baseXP = 20;
    const canAddBase = Math.max(0, 250 - user.xp_per_day);
    const baseAdded = Math.min(baseXP, canAddBase);
    user.xp_per_day += baseAdded;
    user.xp += baseAdded;
    const currentFollowers = user.followers?.length || 0;
    const milestones = [
      { count: 10, bonusXP: 100 },
      { count: 50, bonusXP: 300 },
      { count: 100, bonusXP: 800 },
      { count: 500, bonusXP: 3000 },
      { count: 1000, bonusXP: 7000 },
    ];
    user.milestonesReached ??= [];
    for (const m of milestones) {
      if (
        currentFollowers >= m.count &&
        !user.milestonesReached.includes(m.count)
      ) {
        const canAddBonus = Math.max(0, 250 - user.xp_per_day);
        const bonusAdded = Math.min(canAddBonus, m.bonusXP);
        user.xp_per_day += bonusAdded;
        user.xp += bonusAdded;
        user.milestonesReached.push(m.count);
        this.logger.log(
          `User ${user.username} đạt mốc ${m.count}. Bonus ${bonusAdded} XP.`,
        );
      }
    }
    await user.save();
  }

  async GetUserDental(id: string) {
    return this.userModel.findById(id).exec();
  }

  async getAllFriend(id: string) {
    const user = await this.userModel.findById(id).populate('friends').exec();
    if (!user) {
      throw new NotFoundException('Người dùng không tồn tại');
    }
    return user.friends;
  }

  async getWarnings(userId: string) {
    const user = await this.userModel
      .findById(userId)
      .select('warnings')
      .populate([
        {
          path: 'warnings.by',
          select: 'username avatar',
        },
        {
          path: 'warnings.reason',
          select: 'reasonText',
        },
      ]);

    if (!user) throw new NotFoundException('Người dùng không tồn tại.');

    return user.warnings;
  }

  async deleteWarning(userId: string, warningId: string) {
    const user = await this.userModel.findById(userId);
    if (!user) throw new NotFoundException('Người dùng không tồn tại.');

    const warningIndex = user.warnings.findIndex(
      (w: any) => w._id?.toString() === warningId,
    );

    if (warningIndex === -1)
      throw new NotFoundException('Cảnh cáo không tồn tại.');

    user.warnings.splice(warningIndex, 1);
    await user.save();

    return { message: 'Xoá cảnh cáo thành công.' };
  }

  async getMe(userId: string | Types.ObjectId) {
    const me = await this.userModel
      .findById(userId)
      .select(
        'username email avatar coins hasSelectedInterests globalRole friends currentGame coverImage equippedAvatarFrame'
      )
      .populate({ path: 'equippedAvatarFrame', select: 'assetUrl type' })
      .lean()
      .exec();

    if (!me) throw new NotFoundException('Không tìm thấy người dùng');
    return me;
  }
}
