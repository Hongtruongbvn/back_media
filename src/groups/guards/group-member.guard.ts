import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { GroupMember, GroupMemberDocument } from '../schemas/group-member.schema';

@Injectable()
export class GroupMemberGuard implements CanActivate {
  constructor(
    @InjectModel(GroupMember.name) private groupMemberModel: Model<GroupMemberDocument>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const user = request.user;
    const groupId = request.params.id || request.params.groupId;

    const membership = await this.groupMemberModel.findOne({
      user: user._id,
      group: groupId,
    });

    if (membership) {
      return true; // Cho phép nếu là thành viên
    }

    throw new UnauthorizedException('Chỉ thành viên của nhóm mới có quyền mời.');
  }
}