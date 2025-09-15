// File: apps/api/src/livestream/livestream.service.ts (Cập nhật)
import { Injectable } from '@nestjs/common';
import { UserDocument } from '../auth/schemas/user.schema';

@Injectable()
export class LivestreamService {
  // Map này sẽ lưu thông tin chi tiết về các luồng stream đang hoạt động
  private activeStreams: Map<string, any> = new Map();

  // SỬA LỖI: Thêm tham số `quality` để lưu lại chất lượng của stream
  startStream(user: UserDocument, quality: '720p' | '1080p' | '1440p') {
    this.activeStreams.set(user.id, {
      user: {
        id: user.id,
        username: user.username,
        avatar: user.avatar,
      },
      quality: quality, // Lưu lại chất lượng stream
      startedAt: new Date(),
    });
    console.log(`Livestream started by ${user.username} at ${quality}`);
    return { message: `Livestream started at ${quality}` };
  }

  endStream(userId: string) {
    const stream = this.activeStreams.get(userId);
    if (stream) {
      this.activeStreams.delete(userId);
      console.log(`Livestream ended for user ${userId}`);
      return { message: 'Livestream ended' };
    }
    return { message: 'No active livestream to end' };
  }

  getActiveStreams() {
    return Array.from(this.activeStreams.values());
  }
}