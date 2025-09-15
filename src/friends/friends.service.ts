import {
  Injectable,
  BadRequestException,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from '../auth/schemas/user.schema';
import {
  FriendRequest,
  FriendRequestDocument,
  FriendRequestStatus,
} from './schemas/friend-request.schema';
import { NotificationType } from '../notifications/schemas/notification.schema';
import { EventEmitter2 } from '@nestjs/event-emitter'; // 1. Import

@Injectable()
export class FriendsService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    @InjectModel(FriendRequest.name)
    private friendRequestModel: Model<FriendRequestDocument>,
    private readonly eventEmitter: EventEmitter2, // 2. Inject
  ) {}

  // ✅ HÀM NÀY ĐÃ ĐƯỢC HOÀN THIỆN
  async sendRequest(
    sender: UserDocument,
    recipientId: string,
  ): Promise<FriendRequest> {
    if (sender._id.toString() === recipientId) {
      throw new BadRequestException('Bạn không thể tự kết bạn với chính mình.');
    }

    // Kiểm tra xem đã là bạn bè chưa
    const isAlreadyFriend = sender.friends.some(
      (friendId) => friendId.toString() === recipientId,
    );
    if (isAlreadyFriend) {
      throw new ConflictException('Bạn và người này đã là bạn bè.');
    }

    // Kiểm tra xem đã có yêu cầu (từ một trong hai phía) đang chờ chưa
    const existingRequest = await this.friendRequestModel.findOne({
      $or: [
        { sender: sender._id, recipient: recipientId },
        { sender: recipientId, recipient: sender._id },
      ],
      status: 'PENDING',
    });

    if (existingRequest) {
      throw new ConflictException('Đã có một lời mời kết bạn đang chờ xử lý.');
    }

    const newRequest = new this.friendRequestModel({
      sender: sender._id,
      recipient: recipientId,
    });
    const savedRequest = await newRequest.save();

    // 3. ✅ PHÁT SỰ KIỆN ĐỂ TẠO THÔNG BÁO
    this.eventEmitter.emit('notification.create', {
      recipientId: recipientId, // Người nhận thông báo
      actor: sender, // Người thực hiện hành động
      type: NotificationType.FRIEND_REQUEST,
      link: `/profile/${sender.username}/requests`, // Link đến trang quản lý lời mời
    });

    return savedRequest;
  }

  async getMyFriends(user: UserDocument) {
    const userData = await this.userModel
      .findById(user._id)
      .populate('friends', 'username avatar');
    return userData ? userData.friends : [];
  }

  // --- CÁC HÀM MỚI ---
  async removeFriend(userId: string, friendId: string): Promise<User> {
    const user = await this.userModel.findById(userId);
    const friend = await this.userModel.findById(friendId);

    if (!user || !friend) {
      throw new NotFoundException('Không tìm thấy người dùng.');
    }

    // Xóa bạn khỏi danh sách của cả hai
    await this.userModel.findByIdAndUpdate(userId, {
      $pull: { friends: friendId },
    });
    await this.userModel.findByIdAndUpdate(friendId, {
      $pull: { friends: userId },
    });

    return user;
  }

  async blockUser(userId: string, userToBlockId: string): Promise<User> {
    if (userId === userToBlockId) {
      throw new BadRequestException('Bạn không thể tự chặn chính mình.');
    }
    // Xóa bạn bè trước khi chặn (nếu có)
    await this.removeFriend(userId, userToBlockId);

    const user = await this.userModel.findByIdAndUpdate(
      userId,
      { $addToSet: { blockedUsers: userToBlockId } }, // $addToSet để tránh trùng lặp
      { new: true },
    );

    if (!user) {
      throw new NotFoundException('Không tìm thấy người dùng.');
    }
    return user;
  }

  async unblockUser(userId: string, userToUnblockId: string): Promise<User> {
    const user = await this.userModel.findByIdAndUpdate(
      userId,
      { $pull: { blockedUsers: userToUnblockId } },
      { new: true },
    );

    if (!user) {
      throw new NotFoundException('Không tìm thấy người dùng.');
    }
    return user;
  }

  // ✅ BỔ SUNG LẠI HÀM BỊ THIẾU
  async respondToRequest(
    user: UserDocument,
    requestId: string,
    status: FriendRequestStatus.ACCEPTED | FriendRequestStatus.REJECTED,
  ) {
    const request = await this.friendRequestModel.findById(requestId);

    // Kiểm tra xem yêu cầu có tồn tại và có đúng là gửi cho bạn không
    if (!request || request.recipient.toString() !== user._id.toString()) {
      throw new NotFoundException('Không tìm thấy lời mời kết bạn.');
    }
    if (request.status !== FriendRequestStatus.PENDING) {
      throw new BadRequestException('Lời mời này đã được xử lý.');
    }

    // Cập nhật trạng thái yêu cầu
    request.status = status;
    await request.save();

    // Nếu chấp nhận, thêm vào danh sách bạn bè của cả hai người
    if (status === FriendRequestStatus.ACCEPTED) {
      const sender = await this.userModel.findById(request.sender);
      if (!sender)
        throw new NotFoundException('Không tìm thấy người gửi yêu cầu.');

      // Thêm vào danh sách bạn bè của nhau
      await this.userModel.findByIdAndUpdate(request.sender, {
        $addToSet: { friends: request.recipient },
      });
      await this.userModel.findByIdAndUpdate(request.recipient, {
        $addToSet: { friends: request.sender },
      });

      // Phát sự kiện thông báo cho người gửi rằng bạn đã chấp nhận
      this.eventEmitter.emit('notification.create', {
        recipientId: sender._id.toString(),
        actor: user,
        type: NotificationType.FRIEND_REQUEST_ACCEPTED, // Cần thêm type này vào enum
        link: `/profile/${user.username}`,
      });
    }

    // Xóa yêu cầu sau khi đã xử lý
    await this.friendRequestModel.findByIdAndDelete(requestId);

    return {
      message: `Đã ${status === 'ACCEPTED' ? 'chấp nhận' : 'từ chối'} lời mời.`,
    };
  } // friends.service.ts

  async getAllRequests(user: UserDocument) {
    return this.friendRequestModel
      .find({
        recipient: user._id,
        status: 'PENDING',
      })
      .populate('sender', 'username avatar');
  }
}
