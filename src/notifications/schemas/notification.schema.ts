import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { User } from '../../auth/schemas/user.schema';

export type NotificationDocument = Notification & Document;

// ============ Các loại thông báo ============
export enum NotificationType {
  NEW_REACTION = 'NEW_REACTION',
  NEW_COMMENT = 'NEW_COMMENT',
  NEW_FOLLOWER = 'NEW_FOLLOWER',

  FRIEND_REQUEST = 'FRIEND_REQUEST',
  // Một số nơi FE dùng 'FRIEND_ACCEPTED', nên mình giữ giá trị string này:
  FRIEND_REQUEST_ACCEPTED = 'FRIEND_ACCEPTED',
  // (tuỳ chọn) thêm alias để đỡ nhầm tên
  // FRIEND_ACCEPTED = 'FRIEND_ACCEPTED',

  GAME_INVITE = 'GAME_INVITE',
  NEW_NOTIFICATION = 'NEW_NOTIFICATION',
  WARN = 'WARN',

  GROUP_REQUEST_ACCEPTED = 'GROUP_REQUEST_ACCEPTED',
  GROUP_REQUEST_REJECTED = 'GROUP_REQUEST_REJECTED',

  GROUP_INVITE = 'GROUP_INVITE',
  GROUP_INVITE_ACCEPTED = 'GROUP_INVITE_ACCEPTED',
  GROUP_INVITE_DECLINED = 'GROUP_INVITE_DECLINED',

  POST_DELETED_BY_ADMIN = 'POST_DELETED_BY_ADMIN',
  NEW_REPLY = 'NEW_REPLY',
}

@Schema({ timestamps: true })
export class Notification {
  @Prop({ required: true, type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  recipient: User; // Người nhận

  @Prop({ required: true, type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  sender: User; // Tác nhân

  // Khai báo rõ kiểu string + enum các giá trị hợp lệ
  @Prop({ type: String, enum: Object.values(NotificationType), required: true })
  type: NotificationType;

  @Prop({ default: false })
  isRead: boolean;

  @Prop({ type: String })
  link?: string;

  // Cho phép đính kèm dữ liệu linh hoạt (inviteId, groupId, reason, ...)
  @Prop({ type: Object })
  metadata?: {
    gameName?: string;
    boxArtUrl?: string;
    reason?: string;
    reportReason?: string;
    postContent?: string;
    groupName?: string;
    inviteId?: string;
    groupId?: string;
  };
}

export const NotificationSchema = SchemaFactory.createForClass(Notification);

// Index phổ biến: lấy theo người nhận, sắp xếp mới nhất
NotificationSchema.index({ recipient: 1, createdAt: -1 });
