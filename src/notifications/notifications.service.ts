import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { DeleteResult, Model } from 'mongoose';
import { OnEvent } from '@nestjs/event-emitter';

import {
  Notification,
  NotificationDocument,
  NotificationType,
} from './schemas/notification.schema';
import { User, UserDocument } from '../auth/schemas/user.schema';
import { NotificationsGateway } from './notifications.gateway';
import { PresenceService } from '../presence/presence.service';

type CreateNotificationEvent = {
  recipientId: string;
  actor?: UserDocument;                 // optional cho thông báo hệ thống
  type: NotificationType;
  link?: string | null;
  metadata?: Record<string, any>;       // ⬅️ thêm để giữ groupId, inviteId,...
};

@Injectable()
export class NotificationsService {
  constructor(
    @InjectModel(Notification.name)
    private notificationModel: Model<NotificationDocument>,
    @InjectModel(User.name)
    private userModel: Model<UserDocument>,
    private notificationsGateway: NotificationsGateway,
    private presenceService: PresenceService,
  ) {}

  // Tạo + push realtime
  async createNotification(
    recipient: UserDocument,
    sender: UserDocument | null | undefined, // ⬅️ cho phép optional
    type: NotificationType,
    link: string | null,
    metadata?: any,
  ) {
    // Không gửi cho chính mình (nếu có sender)
    if (sender && recipient._id.toString() === sender._id.toString()) return;

    const payload: any = {
      recipient: recipient._id,
      type,
      link,
      metadata,
    };
    if (sender) payload.sender = sender._id;

    const notification = new this.notificationModel(payload);

    const savedNotification = await notification.save();
    const populatedNotification = await savedNotification.populate(
      'sender',
      'username avatar',
    );

    // Gửi realtime nếu online
    if (await this.presenceService.isUserOnline(recipient._id.toString())) {
      const socketId = this.presenceService.getSocketId(
        recipient._id.toString(),
      );
      if (socketId) {
        this.notificationsGateway.sendNotificationToUser(
          socketId,
          populatedNotification,
        );
      }
    }
    return populatedNotification;
  }

  async getNotificationsForUser(userId: string): Promise<Notification[]> {
    return this.notificationModel
      .find({ recipient: userId })
      .populate('sender', 'username avatar')
      .sort({ createdAt: -1 })
      .exec();
  }

  async markAsRead(
    notificationId: string,
    userId: string,
  ): Promise<Notification | null> {
    return this.notificationModel.findOneAndUpdate(
      { _id: notificationId, recipient: userId },
      { isRead: true },
      { new: true },
    );
  }

  async getAllNotification(recivedId: string) {
    const notifications = await this.notificationModel
      .find({ recipient: recivedId })
      .sort({ createdAt: -1 })
      .populate('sender', 'username avatar')
      .exec();
    return notifications;
  }

  // Lắng nghe sự kiện tạo thông báo từ các module khác
  @OnEvent('notification.create')
  async handleNotificationCreateEvent(payload: CreateNotificationEvent) {
    const recipient = await this.userModel.findById(payload.recipientId);
    if (!recipient) {
      console.error(
        `Không tìm thấy người nhận thông báo: ${payload.recipientId}`,
      );
      return;
    }

    await this.createNotification(
      recipient,
      payload.actor ?? null, // ⬅️ giữ nguyên actor nếu có
      payload.type,
      payload.link ?? null,
      payload.metadata ?? undefined, // ⬅️ GHI metadata
    );
  }

  async deleteNotification(notificationId: string, userId: string) {
    return this.notificationModel.findOneAndDelete({
      _id: notificationId,
      recipient: userId,
    });
  }

  async clearAllNotifications(userId: string): Promise<DeleteResult> {
    return this.notificationModel.deleteMany({ recipient: userId });
  }
}
