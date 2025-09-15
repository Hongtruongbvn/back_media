import { Controller, Get, Param, Post, Query, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';
import { UserDocument } from '../auth/schemas/user.schema';
import { GroupsService } from './groups.service';

@UseGuards(JwtAuthGuard)
@Controller('group-invites')
export class GroupInvitesController {
  constructor(private readonly groupsService: GroupsService) {}

  // FE dùng để liệt kê lời mời của tôi (tuỳ chọn status, mặc định PENDING)
  @Get('me')
  getMyInvites(
    @GetUser() user: UserDocument,
    @Query('status') status?: 'PENDING' | 'ACCEPTED' | 'DECLINED' | 'CANCELED',
  ) {
    return this.groupsService.getMyInvites(user, status);
  }

  // FE: POST /group-invites/:inviteId/accept
  @Post(':inviteId/accept')
  accept(@GetUser() user: UserDocument, @Param('inviteId') inviteId: string) {
    return this.groupsService.acceptInvite(inviteId, user);
  }

  // FE: POST /group-invites/:inviteId/decline
  @Post(':inviteId/decline')
  decline(@GetUser() user: UserDocument, @Param('inviteId') inviteId: string) {
    return this.groupsService.declineInvite(inviteId, user);
  }
}
