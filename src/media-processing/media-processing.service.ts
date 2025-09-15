import { Injectable, Logger } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { ModerationService } from '../moderation/moderation.service';
import { Post, PostDocument, ModerationStatus } from '../posts/schemas/post.schema';

@Injectable()
export class MediaProcessingService {
  private readonly logger = new Logger(MediaProcessingService.name);

  constructor(
    private moderationService: ModerationService,
    @InjectModel(Post.name) private postModel: Model<PostDocument>,
  ) {}

  @OnEvent('post.video.uploaded')
  async handleVideoModeration(payload: { postId: string; videoPath: string }) {
    this.logger.log(`Bắt đầu xử lý video cho bài đăng: ${payload.postId}`);

    // Mô phỏng quá trình xử lý video nặng (cắt khung hình, gọi AI...)
    // Trong thực tế, đây là nơi bạn dùng FFmpeg
    await new Promise(resolve => setTimeout(resolve, 15000)); // Giả lập chờ 15 giây

    // Mô phỏng kết quả kiểm duyệt (giả sử video này ổn)
    const moderationResult = { status: ModerationStatus.APPROVED };

    // Cập nhật trạng thái bài đăng sau khi xử lý xong
    await this.postModel.findByIdAndUpdate(payload.postId, {
        $set: { moderationStatus: moderationResult.status },
    });

    this.logger.log(`Hoàn tất xử lý video cho bài đăng: ${payload.postId}`);
    // (Nâng cao) Gửi thông báo cho người dùng rằng video của họ đã được duyệt
  }
}