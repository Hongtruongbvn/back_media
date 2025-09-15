import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import {
  User,
  UserDocument,
  GlobalRole,
  AccountStatus,
} from '../auth/schemas/user.schema';
import {
  Post,
  PostDocument,
  ModerationStatus,
} from '../posts/schemas/post.schema';
import { Comment, CommentDocument } from '../posts/schemas/comment.schema';
import { NotificationsService } from 'src/notifications/notifications.service';
import { NotificationType } from 'src/notifications/schemas/notification.schema';

@Injectable()
export class AdminService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    @InjectModel(Post.name) private postModel: Model<PostDocument>,
    @InjectModel(Comment.name) private commentModel: Model<CommentDocument>,
  ) {}

  async getAllUsers(): Promise<User[]> {
    return this.userModel.find().select('-password').exec();
  }

  async updateUserRole(userId: string, role: GlobalRole): Promise<User> {
    const user = await this.userModel.findByIdAndUpdate(
      userId,
      { globalRole: role },
      { new: true },
    );
    if (!user) {
      throw new NotFoundException('Không tìm thấy người dùng.');
    }
    return user;
  }

  // --- HÀM MỚI ---
  async suspendUser(
    userId: string,
    reason: string,
    durationInDays: number,
    admin: UserDocument,
  ): Promise<User> {
    const user = await this.userModel.findById(userId);
    if (!user) throw new NotFoundException('Không tìm thấy người dùng.');

    const suspensionExpires = new Date();
    suspensionExpires.setDate(suspensionExpires.getDate() + durationInDays);

    user.accountStatus = AccountStatus.SUSPENDED;
    user.suspensionExpires = suspensionExpires;

    // (Tùy chọn) Thêm một cảnh báo để ghi lại lý do
    user.warnings.push({
      _id: new Types.ObjectId(),
      reason: `Tạm khóa: ${reason}`,
      date: new Date(),
      by: admin._id,
    });

    return user.save();
  }

  async banUser(
    userId: string,
    reason: string,
    admin: UserDocument,
  ): Promise<User> {
    const user = await this.userModel.findById(userId);
    if (!user) throw new NotFoundException('Không tìm thấy người dùng.');

    user.accountStatus = AccountStatus.BANNED;
    user.suspensionExpires = undefined; // Xóa ngày hết hạn nếu có

    user.warnings.push({
      _id: new Types.ObjectId(),
      reason: `Khóa vĩnh viễn: ${reason}`,
      date: new Date(),
      by: admin._id,
    });

    return user.save();
  }

  async warnUser(
    userId: string,
    reason: string,
    admin: UserDocument,
  ): Promise<User> {
    const user = await this.userModel.findById(userId);
    if (!user) throw new NotFoundException('Không tìm thấy người dùng.');
    user.warnings.push({
      _id: new Types.ObjectId(),
      reason: `cảnh cáo :${reason}`,
      date: new Date(),
      by: admin._id,
    });
    return user.save();
  }
  async restoreUser(userId: string, admin: UserDocument): Promise<any> {
    const user = await this.userModel.findById(userId);
    if (!user) throw new NotFoundException('Không tìm thấy người dùng.');
    user.accountStatus = AccountStatus.ACTIVE;
    user.suspensionExpires = undefined;

    // In your service where you add warnings
    user.warnings.push({
      _id: new Types.ObjectId(), // This can be omitted if using the schema default
      reason: `Khôi phục trạng thái hoạt động bởi Admin`,
      date: new Date(),
      by: admin.id,
    });
    await user.save();
  }

  async getModerationQueue(): Promise<{ posts: Post[]; comments: Comment[] }> {
    const posts = await this.postModel
      .find({
        moderationStatus: {
          $in: [ModerationStatus.PENDING, ModerationStatus.PROCESSING],
        },
      })
      .populate('author', 'username avatar')
      .sort({ createdAt: 'desc' })
      .exec();

    const comments = await this.commentModel
      .find({ moderationStatus: ModerationStatus.PENDING })
      .populate('author', 'username avatar')
      .populate('post', 'content') // Thêm thông tin bài đăng gốc
      .sort({ createdAt: 'desc' })
      .exec();

    return { posts, comments };
  }

  /**
   * Cập nhật trạng thái của một bài đăng
   */
  async updatePostStatus(
    postId: string,
    status: ModerationStatus.APPROVED | ModerationStatus.REJECTED,
  ): Promise<Post> {
    const post = await this.postModel.findByIdAndUpdate(
      postId,
      { moderationStatus: status },
      { new: true },
    );
    if (!post) throw new NotFoundException('Không tìm thấy bài đăng.');
    // (Nâng cao) Gửi thông báo cho người dùng về kết quả kiểm duyệt
    return post;
  }

  /**
   * Cập nhật trạng thái của một bình luận
   */
  async updateCommentStatus(
    commentId: string,
    status: ModerationStatus.APPROVED | ModerationStatus.REJECTED,
  ): Promise<Comment> {
    const comment = await this.commentModel.findByIdAndUpdate(
      commentId,
      { moderationStatus: status },
      { new: true },
    );
    if (!comment) throw new NotFoundException('Không tìm thấy bình luận.');
    return comment;
  }

  /**
   * Xóa vĩnh viễn một bài đăng (quyền Admin)
   */
  async forceDeletePost(postId: string): Promise<{ message: string }> {
    const result = await this.postModel.findByIdAndDelete(postId);
    if (!result) throw new NotFoundException('Không tìm thấy bài đăng.');
    // Xóa tất cả bình luận liên quan
    await this.commentModel.deleteMany({ post: postId });
    return { message: 'Đã xóa vĩnh viễn bài đăng và các bình luận liên quan.' };
  }
  async getStats() {
    const [totalUsers, totalPosts, bannedUsers, pendingModeration] =
      await Promise.all([
        this.userModel.countDocuments(),
        this.postModel.countDocuments(),
        this.userModel.countDocuments({ accountStatus: 'BANNED' }),
        this.postModel.countDocuments({ status: 'PENDING' }),
      ]);

    return {
      totalUsers,
      totalPosts,
      bannedUsers,
      pendingModeration,
    };
  }
}
