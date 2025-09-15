import {
  Controller,
  Get,
  UseGuards,
  Patch,
  Param,
  Body,
  Post,
  Delete,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { GlobalRole, UserDocument } from '../auth/schemas/user.schema';
import { AdminService } from './admin.service';
import { UpdateRoleDto } from './dto/update-role.dto';
import { GetUser } from '../auth/decorators/get-user.decorator';
import { SuspendUserDto } from './dto/suspend-user.dto';
import { BanUserDto } from './dto/ban-user.dto';
import { WarnUserDto } from './dto/warn-user.dto';
import { UpdateModerationStatusDto } from './dto/update-moderation-status.dto'; // Import DTO mới

@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(GlobalRole.ADMIN)
@Controller('admin')
export class AdminController {
  constructor(private adminService: AdminService) {}

  @Get('users')
  getAllUsers() {
    return this.adminService.getAllUsers();
  }

  @Patch('users/:id/role')
  updateUserRole(
    @Param('id') userId: string,
    @Body() updateRoleDto: UpdateRoleDto,
  ) {
    return this.adminService.updateUserRole(userId, updateRoleDto.role);
  }

  // --- ENDPOINTS MỚI ---
  @Post('users/:id/warn')
  warnUser(
    @Param('id') userId: string,
    @Body() warnUserDto: WarnUserDto,
    @GetUser() admin: UserDocument,
  ) {
    return this.adminService.warnUser(userId, warnUserDto.reason, admin);
  }

  @Post('users/:id/suspend')
  suspendUser(
    @Param('id') userId: string,
    @Body() suspendUserDto: SuspendUserDto,
    @GetUser() admin: UserDocument,
  ) {
    return this.adminService.suspendUser(
      userId,
      suspendUserDto.reason,
      suspendUserDto.durationInDays,
      admin,
    );
  }

  @Post('users/:id/ban')
  banUser(
    @Param('id') userId: string,
    @Body() banUserDto: BanUserDto,
    @GetUser() admin: UserDocument,
  ) {
    return this.adminService.banUser(userId, banUserDto.reason, admin);
  }
  @Post('users/:id/restore')
  async restoreUser(
    @Param('id') userId: string,
    @GetUser() admin: UserDocument,
  ) {
    return this.adminService.restoreUser(userId, admin);
  }

  @Get('moderation-queue')
  getModerationQueue() {
    return this.adminService.getModerationQueue();
  }

  @Patch('posts/:id/status')
  updatePostStatus(
    @Param('id') postId: string,
    @Body() updateStatusDto: UpdateModerationStatusDto,
  ) {
    return this.adminService.updatePostStatus(postId, updateStatusDto.status);
  }

  @Patch('comments/:id/status')
  updateCommentStatus(
    @Param('id') commentId: string,
    @Body() updateStatusDto: UpdateModerationStatusDto,
  ) {
    return this.adminService.updateCommentStatus(
      commentId,
      updateStatusDto.status,
    );
  }

  @Delete('posts/:id')
  @HttpCode(HttpStatus.OK)
  forceDeletePost(@Param('id') postId: string) {
    return this.adminService.forceDeletePost(postId);
  }
  @Get('stats')
  getStats() {
    return this.adminService.getStats();
  }
}
