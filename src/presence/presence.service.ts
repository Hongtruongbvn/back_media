// File: api/src/presence/presence.service.ts
import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument, PresenceStatus } from '../auth/schemas/user.schema';

@Injectable()
export class PresenceService {
  /**
   * userId -> Set<socketId>
   * Hỗ trợ nhiều tab/socket cho cùng một tài khoản.
   */
  private readonly socketsByUser = new Map<string, Set<string>>();

  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

  /* ============ Socket registry ============ */

  /** Đăng ký 1 socket cho user */
  addUser(userId: string, socketId: string) {
    const id = String(userId);
    const set = this.socketsByUser.get(id) ?? new Set<string>();
    set.add(socketId);
    this.socketsByUser.set(id, set);
  }

  /**
   * Gỡ socket khỏi user. Trả về userId nếu socket này thuộc về user nào đó.
   * Nếu user không còn socket nào -> đồng nghĩa offline theo RAM.
   */
  removeUserBySocketId(socketId: string): string | null {
    for (const [userId, set] of this.socketsByUser.entries()) {
      if (set.has(socketId)) {
        set.delete(socketId);
        if (set.size === 0) this.socketsByUser.delete(userId);
        else this.socketsByUser.set(userId, set);
        return userId;
      }
    }
    return null;
  }

  /** Lấy danh sách socketId của user (có thể rỗng) */
  getSocketIds(userId: string): string[] {
    return Array.from(this.socketsByUser.get(String(userId)) ?? []);
  }

  /** Giữ API cũ — trả socket đầu tiên nếu cần */
  getSocketId(userId: string): string | undefined {
    const ids = this.getSocketIds(userId);
    return ids[0];
  }

  /* ============ Trạng thái online/offline ============ */

  /**
   * Kiểm tra online theo DB + RAM:
   * - DB: presenceStatus !== OFFLINE
   * - RAM: đang có ít nhất 1 socket kết nối
   */
  async isUserOnline(userId: string): Promise<boolean> {
    const user = await this.userModel.findById(userId).select('presenceStatus').lean();
    if (!user || (user as any).presenceStatus === PresenceStatus.OFFLINE) return false;
    return (this.socketsByUser.get(String(userId))?.size ?? 0) > 0;
  }

  /** Cập nhật presenceStatus trực tiếp (nội bộ dùng) */
  async setPresenceStatus(userId: string, status: PresenceStatus): Promise<User | null> {
    return this.userModel.findByIdAndUpdate(userId, { presenceStatus: status }, { new: true });
  }

  /** Đánh dấu ONLINE trong DB (gọi khi có kết nối đầu tiên của user) */
  async setOnline(userId: string): Promise<void> {
    try {
      await this.userModel.findByIdAndUpdate(
        userId,
        { presenceStatus: PresenceStatus.ONLINE },
        { new: false }
      ).lean();
    } catch {}
  }

  /**
   * Đánh dấu OFFLINE trong DB (gọi khi user không còn socket nào).
   * Nếu schema có trường `lastSeenAt`, sẽ ghi lại thời điểm cuối.
   */
  async setOffline(userId: string, lastSeen?: number): Promise<void> {
    try {
      const update: any = { presenceStatus: PresenceStatus.OFFLINE };
      if (typeof lastSeen === 'number') update.lastSeenAt = new Date(lastSeen);
      await this.userModel.findByIdAndUpdate(userId, update, { new: false }).lean();
    } catch {}
  }
}
