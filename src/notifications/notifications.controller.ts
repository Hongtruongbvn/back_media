// notifications.controller.ts
import {
  Controller,
  Get,
  Param,
  Patch,
  UseGuards,
  Delete,
} from '@nestjs/common';
import { NotificationsService } from './notifications.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';
import { UserDocument } from '../auth/schemas/user.schema';
import { DeleteResult } from 'mongoose';

@UseGuards(JwtAuthGuard)
@Controller('notifications')
export class NotificationsController {
  constructor(private readonly notificationsService: NotificationsService) {}

  @Get()
  getNotifications(@GetUser() user: UserDocument) {
    return this.notificationsService.getNotificationsForUser(
      user._id.toString(),
    );
  }

  @Patch(':id/read')
  markAsRead(
    @Param('id') notificationId: string,
    @GetUser() user: UserDocument,
  ) {
    return this.notificationsService.markAsRead(
      notificationId,
      user._id.toString(),
    );
  }

  @Get('/all')
  async getMyNotifications(@GetUser() user: UserDocument) {
    return this.notificationsService.getAllNotification(user._id.toString());
  }

  @Delete(':id')
  async deleteNotification(
    @Param('id') notificationId: string,
    @GetUser() user: UserDocument,
  ) {
    return this.notificationsService.deleteNotification(
      notificationId,
      user._id.toString(),
    );
  }

  @Delete('/clear')
  async clearAllNotifications(
    @GetUser() user: UserDocument,
  ): Promise<DeleteResult> {
    return this.notificationsService.clearAllNotifications(user._id.toString());
  }
}
