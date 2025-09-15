import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { GroupMember, GroupMemberDocument, GroupRole } from '../schemas/group-member.schema';

@Injectable()
export class GroupOwnerGuard implements CanActivate {
  constructor(
    @InjectModel(GroupMember.name) private groupMemberModel: Model<GroupMemberDocument>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const user = request.user; // Lấy từ JwtAuthGuard
    const groupId = request.params.id || request.params.groupId;

    if (!user || !groupId) {
      throw new UnauthorizedException('Yêu cầu không hợp lệ');
    }

    const membership = await this.groupMemberModel.findOne({
      user: user._id,
      group: groupId,
    });

    if (membership && membership.role === GroupRole.OWNER) {
      return true; // Cho phép truy cập nếu là OWNER
    }

    throw new UnauthorizedException('Bạn không có quyền thực hiện hành động này.');
  }
}