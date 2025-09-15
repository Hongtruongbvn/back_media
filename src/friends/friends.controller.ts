import {
  Controller,
  Post,
  Get,
  Param,
  Body,
  UseGuards,
  Delete,
} from '@nestjs/common';
import { FriendsService } from './friends.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';
import { UserDocument } from '../auth/schemas/user.schema';
import { FriendRequestStatus } from './schemas/friend-request.schema';

@UseGuards(JwtAuthGuard)
@Controller('friends')
export class FriendsController {
  constructor(private readonly friendsService: FriendsService) {}

  // ✅ TẠO ENDPOINT NÀY: POST /api/friends/request/:receiverId
  @Post('request/:receiverId')
  sendRequest(
    @GetUser() sender: UserDocument,
    @Param('receiverId') receiverId: string,
  ) {
    return this.friendsService.sendRequest(sender, receiverId);
  }

  @Post('response/:requestId')
  respondToRequest(
    @GetUser() user: UserDocument,
    @Param('requestId') requestId: string,
    @Body('status')
    status: FriendRequestStatus.ACCEPTED | FriendRequestStatus.REJECTED,
  ) {
    return this.friendsService.respondToRequest(user, requestId, status);
  }

  @Get('me')
  getMyFriends(@GetUser() user: UserDocument) {
    return this.friendsService.getMyFriends(user);
  }

  // --- CÁC ENDPOINT MỚI ---
  @Delete(':friendId')
  removeFriend(
    @GetUser() user: UserDocument,
    @Param('friendId') friendId: string,
  ) {
    return this.friendsService.removeFriend(user.id, friendId);
  }

  @Post('block/:userId')
  blockUser(
    @GetUser() user: UserDocument,
    @Param('userId') userIdToBlock: string,
  ) {
    return this.friendsService.blockUser(user.id, userIdToBlock);
  }

  @Delete('block/:userId')
  unblockUser(
    @GetUser() user: UserDocument,
    @Param('userId') userIdToUnblock: string,
  ) {
    return this.friendsService.unblockUser(user.id, userIdToUnblock);
  }

  // friends.controller.ts

  @Get('requests')
  getFriendRequests(@GetUser() user: UserDocument) {
    return this.friendsService.getAllRequests(user);
  }
}
