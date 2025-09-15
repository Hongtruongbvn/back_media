import {
  Controller,
  Get,
  Post,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  Patch,
  UseInterceptors,
  UploadedFile,
} from '@nestjs/common';
import { GroupsService } from './groups.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';
import { UserDocument } from '../auth/schemas/user.schema';
import { CreateGroupDto } from './dto/create-group.dto';
import { UpdateGroupDto } from './dto/update-group.dto';
import { GroupOwnerGuard } from './guards/group-owner.guard';
import { GroupMemberGuard } from './guards/group-member.guard';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { extname } from 'path';

// DTO cho lời mời
import { GetInviteCandidatesDto } from './dto/get-invite-candidates.dto';
import { SendGroupInvitesDto } from './dto/send-group-invites.dto';
import { GetMyInvitesDto } from './dto/get-my-invites.dto';

/* =========================================================
 *       CONTROLLER CHO CÁC ROUTE /groups/...
 * ========================================================= */
@UseGuards(JwtAuthGuard)
@Controller('groups')
export class GroupsController {
  constructor(private readonly groupsService: GroupsService) {}

  @Post()
  create(@GetUser() user: UserDocument, @Body() dto: CreateGroupDto) {
    return this.groupsService.createGroup(user, dto);
  }

  @Get('me')
  findMyGroups(@GetUser() user: UserDocument) {
    return this.groupsService.findGroupsForUser(user);
  }

  @Get('suggestions')
  getSuggestions(@GetUser() user: UserDocument) {
    return this.groupsService.suggestGroups(user);
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.groupsService.findOneById(id);
  }

  // Cập nhật nhóm
  @Patch(':id')
  @UseGuards(GroupOwnerGuard)
  updateGroup(@Param('id') groupId: string, @Body() dto: UpdateGroupDto) {
    return this.groupsService.updateGroup(groupId, dto);
  }

  @Delete(':id')
  @UseGuards(GroupOwnerGuard)
  deleteGroup(@Param('id') groupId: string, @GetUser() user: UserDocument) {
    return this.groupsService.deleteGroup(groupId, user);
  }

  // Bài đăng trong nhóm (chỉ thành viên)
  @Get(':id/posts')
  @UseGuards(GroupMemberGuard)
  getPosts(@Param('id') id: string) {
    return this.groupsService.getPosts(id);
  }

  @Get(':id/join-status')
  getJoinStatus(@GetUser() user: UserDocument, @Param('id') groupId: string) {
    return this.groupsService.getJoinStatus(user, groupId);
  }

  @Post(':id/join')
  join(@GetUser() user: UserDocument, @Param('id') groupId: string) {
    return this.groupsService.joinGroup(user, groupId);
  }

  @Post(':id/leave')
  leaveGroup(@GetUser() user: UserDocument, @Param('id') groupId: string) {
    return this.groupsService.leaveGroup(user, groupId);
  }

  // --- Quản lý yêu cầu join ---
  @Get(':id/requests')
  @UseGuards(GroupOwnerGuard)
  getJoinRequests(@Param('id') groupId: string) {
    return this.groupsService.getJoinRequests(groupId);
  }

  @Post(':id/requests/:requestId/approve')
  @UseGuards(GroupOwnerGuard)
  approveRequest(@GetUser() owner: UserDocument, @Param('requestId') requestId: string) {
    return this.groupsService.approveRequest(requestId, owner);
  }

  @Post(':id/requests/:requestId/reject')
  @UseGuards(GroupOwnerGuard)
  rejectRequest(@GetUser() owner: UserDocument, @Param('requestId') requestId: string) {
    return this.groupsService.rejectRequest(requestId, owner);
  }

  @Get(':id/members')
  @UseGuards(GroupMemberGuard)
  getGroupMembers(@Param('id') groupId: string) {
    return this.groupsService.getGroupMembers(groupId);
  }

  @Delete(':groupId/members/:memberUserId')
  @UseGuards(GroupOwnerGuard)
  kickMember(@Param('groupId') groupId: string, @Param('memberUserId') memberUserId: string) {
    return this.groupsService.kickMember(groupId, memberUserId);
  }

  // --- Lời mời nhóm (trong phạm vi nhóm) ---

  // Mời 1 người (giữ lại nếu cần)
  @Post(':id/invite')
  @UseGuards(GroupMemberGuard)
  createInvite(
    @Param('id') groupId: string,
    @GetUser() inviter: UserDocument,
    @Body('inviteeId') inviteeId: string,
  ) {
    return this.groupsService.createInvite(groupId, inviter, inviteeId);
  }

  // Danh sách bạn bè có thể mời + tìm kiếm
  @Get(':groupId/invites/candidates')
  @UseGuards(GroupMemberGuard)
  getInviteCandidates(
    @GetUser() user: UserDocument,
    @Param('groupId') groupId: string,
    @Query() query: GetInviteCandidatesDto,
  ) {
    return this.groupsService.getInviteCandidates(user, groupId, query.search);
  }

  // Gửi nhiều lời mời một lần
  @Post(':groupId/invites')
  @UseGuards(GroupMemberGuard)
  sendInvites(
    @GetUser() user: UserDocument,
    @Param('groupId') groupId: string,
    @Body() dto: SendGroupInvitesDto,
  ) {
    return this.groupsService.createInvitesBatch(groupId, user, dto.inviteeIds);
  }

  // Upload ảnh nhóm
  @Patch(':id/avatar')
  @UseGuards(GroupOwnerGuard)
  @UseInterceptors(
    FileInterceptor('file', {
      storage: diskStorage({
        destination: './uploads/groups/avatars',
        filename: (req, file, cb) => {
          const randomName = Array(32)
            .fill(null)
            .map(() => Math.round(Math.random() * 16).toString(16))
            .join('');
          cb(null, `${randomName}${extname(file.originalname)}`);
        },
      }),
    }),
  )
  uploadAvatar(@Param('id') groupId: string, @UploadedFile() file: Express.Multer.File) {
    return this.groupsService.updateGroupImage(groupId, file.path, 'avatar');
  }

  @Patch(':id/cover')
  @UseGuards(GroupOwnerGuard)
  @UseInterceptors(
    FileInterceptor('file', {
      storage: diskStorage({
        destination: './uploads/groups/covers',
        filename: (req, file, cb) => {
          const randomName = Array(32)
            .fill(null)
            .map(() => Math.round(Math.random() * 16).toString(16))
            .join('');
          cb(null, `${randomName}${extname(file.originalname)}`);
        },
      }),
    }),
  )
  uploadCover(@Param('id') groupId: string, @UploadedFile() file: Express.Multer.File) {
    return this.groupsService.updateGroupImage(groupId, file.path, 'cover');
  }
}

/* =========================================================
 *       CONTROLLER CHO CÁC ROUTE /group-invites/...
 * ========================================================= */
@UseGuards(JwtAuthGuard)
@Controller('group-invites')
export class MyGroupInvitesController {
  constructor(private readonly groupsService: GroupsService) {}

  // GET /group-invites/me?status=PENDING
  @Get('me')
  myInvites(@GetUser() user: UserDocument, @Query() q: GetMyInvitesDto) {
    return this.groupsService.getMyInvites(user, q.status ?? 'PENDING');
  }

  // POST /group-invites/:id/accept
  @Post(':id/accept')
  accept(@GetUser() user: UserDocument, @Param('id') inviteId: string) {
    return this.groupsService.acceptInvite(inviteId, user);
  }

  // POST /group-invites/:id/decline
  @Post(':id/decline')
  decline(@GetUser() user: UserDocument, @Param('id') inviteId: string) {
    return this.groupsService.declineInvite(inviteId, user);
  }
}
