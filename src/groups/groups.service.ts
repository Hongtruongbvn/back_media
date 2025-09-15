import {
  Injectable,
  NotFoundException,
  ConflictException,
  UnauthorizedException,
  BadRequestException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { Group, GroupDocument } from './schemas/group.schema';
import {
  GroupMember,
  GroupMemberDocument,
  GroupRole,
} from './schemas/group-member.schema';
import { User, UserDocument, GlobalRole } from '../auth/schemas/user.schema';
import { Post, PostDocument } from '../posts/schemas/post.schema';
import { Comment, CommentDocument } from '../posts/schemas/comment.schema';
import {
  JoinRequest,
  JoinRequestDocument,
} from './schemas/join-request.schema';
import { CreateGroupDto } from './dto/create-group.dto';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { NotificationType } from '../notifications/schemas/notification.schema';
import {
  GroupInvite,
  GroupInviteDocument,
} from './schemas/group-invite.schema';
import { UpdateGroupDto } from './dto/update-group.dto';

@Injectable()
export class GroupsService {
  constructor(
    @InjectModel(Group.name) private groupModel: Model<GroupDocument>,
    @InjectModel(GroupMember.name)
    private groupMemberModel: Model<GroupMemberDocument>,
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    @InjectModel(Post.name) private postModel: Model<PostDocument>,
    @InjectModel(Comment.name) private commentModel: Model<CommentDocument>,
    @InjectModel(JoinRequest.name)
    private joinRequestModel: Model<JoinRequestDocument>,
    @InjectModel(GroupInvite.name)
    private groupInviteModel: Model<GroupInviteDocument>,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  // ========= Helpers =========
  private oid(id: string | Types.ObjectId) {
    return typeof id === 'string' ? new Types.ObjectId(id) : id;
  }

  /** Có quyền mời? -> là member & (role cao hoặc group cho phép member mời) */
  private async canInvite(userId: Types.ObjectId, groupId: Types.ObjectId) {
    const member = await this.groupMemberModel
      .findOne({ group: groupId, user: userId })
      .lean();
    if (!member) return false;

    const group = await this.groupModel.findById(groupId).lean();
    const elevated = ['OWNER', 'ADMIN', 'MOD'].includes(member.role as any);
    return elevated || !!(group as any)?.allowMemberInvite;
  }

  // ========= Groups =========

  async createGroup(
    owner: UserDocument,
    createGroupDto: CreateGroupDto,
  ): Promise<Group> {
    const newGroup = new this.groupModel({
      ...createGroupDto,
      owner: owner._id,
      interests: createGroupDto.interestIds,
    });

    const savedGroup = await newGroup.save();

    await new this.groupMemberModel({
      user: owner._id,
      group: savedGroup._id,
      role: GroupRole.OWNER,
    }).save();

    return savedGroup;
  }

  // ✅ Cập nhật thông tin nhóm
  async updateGroup(
    groupId: string,
    updateGroupDto: UpdateGroupDto,
  ): Promise<Group> {
    const updatePayload: any = { ...updateGroupDto };
    if (updateGroupDto.interestIds) {
      updatePayload.interests = updateGroupDto.interestIds;
      delete updatePayload.interestIds;
    }

    const updatedGroup = await this.groupModel.findByIdAndUpdate(
      groupId,
      updatePayload,
      { new: true },
    );

    if (!updatedGroup) {
      throw new NotFoundException(`Không tìm thấy nhóm với ID: ${groupId}`);
    }
    return updatedGroup;
  }

  // ✅ Cập nhật ảnh avatar/cover
  async updateGroupImage(
    groupId: string,
    filePath: string,
    imageType: 'avatar' | 'cover',
  ): Promise<Group> {
    const fieldToUpdate = imageType === 'avatar' ? 'avatar' : 'coverImage';
    const accessiblePath = filePath.replace(/\\/g, '/');
    const normalized =
      accessiblePath.startsWith('/') ? accessiblePath : `/${accessiblePath}`;

    const updatedGroup = await this.groupModel.findByIdAndUpdate(
      groupId,
      { [fieldToUpdate]: normalized },
      { new: true },
    );

    if (!updatedGroup) {
      throw new NotFoundException(`Không tìm thấy nhóm với ID: ${groupId}`);
    }
    return updatedGroup;
  }

  async joinGroup(
    user: UserDocument,
    groupId: string,
  ): Promise<{ message: string }> {
    const group = await this.groupModel.findById(groupId);
    if (!group) throw new NotFoundException('Không tìm thấy nhóm.');

    const existingMembership = await this.groupMemberModel.findOne({
      user: user._id,
      group: groupId,
    });
    if (existingMembership)
      throw new ConflictException('Bạn đã là thành viên của nhóm này.');

    const existingRequest = await this.joinRequestModel.findOne({
      user: user._id,
      group: groupId,
      status: 'PENDING',
    });
    if (existingRequest)
      throw new ConflictException('Bạn đã gửi yêu cầu tham gia nhóm này rồi.');

    if (group.privacy === 'public') {
      await new this.groupMemberModel({
        user: user._id,
        group: groupId,
        role: GroupRole.MEMBER,
      }).save();
      return { message: 'Đã tham gia nhóm thành công.' };
    }

    await new this.joinRequestModel({
      user: user._id,
      group: groupId,
      status: 'PENDING',
    }).save();

    return { message: 'Đã gửi yêu cầu tham gia nhóm. Vui lòng chờ phê duyệt.' };
  }

  // ✅ Lấy bài đăng trong nhóm
  async getPosts(groupId: string) {
    return this.postModel
      .find({ group: new Types.ObjectId(groupId) })
      .sort({ createdAt: -1 })
      .populate('author', '_id fullName username avatar');
  }

  async leaveGroup(user: UserDocument, groupId: string) {
    const membership = await this.groupMemberModel.findOne({
      user: user._id,
      group: groupId,
    });
    if (!membership)
      throw new NotFoundException('Bạn không phải là thành viên của nhóm này.');
    if (membership.role === GroupRole.OWNER)
      throw new BadRequestException(
        'Chủ nhóm không thể rời đi. Bạn cần xóa nhóm hoặc chuyển quyền sở hữu.',
      );

    await membership.deleteOne();
    return this.findOneById(groupId);
  }

  // ========= Invites (MỜI BẠN BÈ) =========

  /**
   * Danh sách bạn bè có thể mời (lọc theo search; loại thành viên hiện tại và invite PENDING)
   * Giả định: User có field `friends: ObjectId[]`
   */
  async getInviteCandidates(
    currentUser: UserDocument,
    groupId: string,
    search?: string,
  ) {
    const uid = this.oid(currentUser._id);
    const gid = this.oid(groupId);

    // Quyền mời
    const can = await this.canInvite(uid, gid);
    if (!can) throw new ForbiddenException('Bạn không có quyền mời vào nhóm này.');

    // 1) danh sách bạn bè
    const me = await this.userModel
      .findById(uid)
      .select('friends')
      .lean<{ friends?: Types.ObjectId[] }>();
    const friendIds = me?.friends ?? [];
    if (friendIds.length === 0) return [];

    // 2) user là member hiện tại
    const members = await this.groupMemberModel
      .find({ group: gid })
      .select('user')
      .lean();
    const memberSet = new Set(members.map((m) => String(m.user)));

    // 3) user đã có invite PENDING
    const pendings = await this.groupInviteModel
      .find({ group: gid, status: 'PENDING' })
      .select('invitee')
      .lean();
    const pendingSet = new Set(pendings.map((p) => String(p.invitee)));

    // 4) lọc
    const filteredIds = friendIds.filter(
      (id) => !memberSet.has(String(id)) && !pendingSet.has(String(id)),
    );
    if (filteredIds.length === 0) return [];

    // 5) áp dụng search (username hoặc fullName)
    const cond: any = { _id: { $in: filteredIds } };
    if (search?.trim()) {
      const kw = search.trim();
      cond.$or = [
        { username: { $regex: kw, $options: 'i' } },
        { fullName: { $regex: kw, $options: 'i' } },
      ];
    }

    const users = await this.userModel
      .find(cond)
      .select('_id username fullName avatar')
      .limit(50)
      .lean();

    return users.map((u) => ({
      id: String(u._id),
      username: (u as any).username,
      fullName: (u as any).fullName,
      avatar: (u as any).avatar,
    }));
  }

  /** Gửi 1 lời mời (giữ lại để dùng khi cần) — đã thêm check quyền + sửa link */
  async createInvite(
    groupId: string,
    inviter: UserDocument,
    inviteeId: string,
  ): Promise<GroupInvite> {
    const gid = this.oid(groupId);
    const can = await this.canInvite(inviter._id, gid);
    if (!can) throw new ForbiddenException('Bạn không có quyền mời vào nhóm này.');

    const invitee = await this.userModel.findById(inviteeId);
    if (!invitee)
      throw new NotFoundException('Không tìm thấy người dùng bạn muốn mời.');

    const isAlreadyMember = await this.groupMemberModel.findOne({
      user: inviteeId,
      group: groupId,
    });
    if (isAlreadyMember)
      throw new ConflictException('Người này đã là thành viên của nhóm.');

    const existingInvite = await this.groupInviteModel.findOne({
      group: groupId,
      invitee: inviteeId,
      status: 'PENDING',
    });
    if (existingInvite)
      throw new ConflictException('Bạn đã mời người này vào nhóm rồi.');

    const savedInvite = await new this.groupInviteModel({
      group: groupId,
      inviter: inviter._id,
      invitee: inviteeId,
      status: 'PENDING',
    }).save();

    this.eventEmitter.emit('notification.create', {
      recipientId: inviteeId,
      actor: inviter,
      type: NotificationType.GROUP_INVITE,
      link: `/notifications`,
      metadata: { groupId, inviteId: savedInvite._id.toString() },
    });

    return savedInvite;
  }

  /** Gửi nhiều lời mời 1 lần */
  async createInvitesBatch(
    groupId: string,
    inviter: UserDocument,
    inviteeIds: string[],
  ): Promise<{ created: number; skipped: number; details: any[] }> {
    const gid = this.oid(groupId);
    const can = await this.canInvite(inviter._id, gid);
    if (!can) throw new ForbiddenException('Bạn không có quyền mời vào nhóm này.');

    const uniqueIds = Array.from(new Set(inviteeIds || [])).filter(Boolean);
    if (uniqueIds.length === 0) {
      throw new BadRequestException('Danh sách người được mời trống.');
    }

    const details: { inviteeId: string; status: 'CREATED' | 'SKIPPED'; reason?: string }[] = [];
    let created = 0;

    for (const inviteeId of uniqueIds) {
      // skip nếu đã là member
      const isMember = await this.groupMemberModel.findOne({
        group: gid,
        user: inviteeId,
      });
      if (isMember) {
        details.push({ inviteeId, status: 'SKIPPED', reason: 'ALREADY_MEMBER' });
        continue;
      }

      // skip nếu đã có PENDING
      const exist = await this.groupInviteModel.findOne({
        group: gid,
        invitee: inviteeId,
        status: 'PENDING',
      });
      if (exist) {
        details.push({ inviteeId, status: 'SKIPPED', reason: 'ALREADY_INVITED' });
        continue;
      }

      // tạo
      const inv = await new this.groupInviteModel({
        group: gid,
        inviter: inviter._id,
        invitee: this.oid(inviteeId),
        status: 'PENDING',
      }).save();
      created++;
      details.push({ inviteeId, status: 'CREATED' });

      // thông báo realtime
      this.eventEmitter.emit('notification.create', {
        recipientId: inviteeId,
        actor: inviter,
        type: NotificationType.GROUP_INVITE,
        link: `/notifications`,
        metadata: { groupId, inviteId: inv._id.toString() },
      });
    }

    return { created, skipped: uniqueIds.length - created, details };
  }

  /** Danh sách lời mời mình nhận */
  async getMyInvites(
    user: UserDocument,
    status: 'PENDING' | 'ACCEPTED' | 'DECLINED' | 'CANCELED' = 'PENDING',
  ) {
    const rows = await this.groupInviteModel
      .find({ invitee: user._id, status })
      .populate('inviter', 'username fullName avatar')
      .populate('group', 'name avatar')
      .sort({ createdAt: -1 })
      .lean();

    return rows.map((r) => ({
      id: String(r._id),
      status: r.status,
      inviter: {
        id: String((r as any).inviter?._id),
        username: (r as any).inviter?.username,
        fullName: (r as any).inviter?.fullName,
        avatar: (r as any).inviter?.avatar,
      },
      group: {
        id: String((r as any).group?._id),
        name: (r as any).group?.name,
        avatar: (r as any).group?.avatar,
      },
      createdAt: r['createdAt'],
    }));
  }

  /** Chấp nhận lời mời */
  async acceptInvite(inviteId: string, user: UserDocument) {
    const inv = await this.groupInviteModel
      .findById(inviteId)
      .populate('group')
      .lean<GroupInvite & { group: any }>();
    if (!inv || String(inv.invitee) !== String(user._id) || inv.status !== 'PENDING') {
      throw new BadRequestException('Lời mời không hợp lệ.');
    }

    // Nếu đã là member thì chỉ đổi trạng thái lời mời
    const existed = await this.groupMemberModel.findOne({
      group: inv.group._id,
      user: user._id,
    });
    if (!existed) {
      await new this.groupMemberModel({
        group: inv.group._id,
        user: user._id,
        role: GroupRole.MEMBER,
      }).save();
    }

    await this.groupInviteModel.findByIdAndUpdate(inviteId, { status: 'ACCEPTED' });

    // Thông báo cho người mời
    this.eventEmitter.emit('notification.create', {
      recipientId: String(inv['inviter']),
      actor: user,
      type: NotificationType.GROUP_INVITE_ACCEPTED,
      link: `/groups/${inv.group._id}`,
      metadata: { groupId: String(inv.group._id), inviteId },
    });

    return { message: 'Bạn đã tham gia nhóm.' };
  }

  /** Từ chối lời mời */
  async declineInvite(inviteId: string, user: UserDocument) {
    const inv = await this.groupInviteModel.findById(inviteId).lean();
    if (!inv || String(inv.invitee) !== String(user._id) || inv.status !== 'PENDING') {
      throw new BadRequestException('Lời mời không hợp lệ.');
    }

    await this.groupInviteModel.findByIdAndUpdate(inviteId, { status: 'DECLINED' });

    // Thông báo cho người mời
    this.eventEmitter.emit('notification.create', {
      recipientId: String(inv['inviter']),
      actor: user,
      type: NotificationType.GROUP_INVITE_DECLINED,
      link: `/notifications`,
      metadata: { groupId: String(inv.group), inviteId },
    });

    return { message: 'Bạn đã từ chối lời mời.' };
  }

  // ========= Khác =========

  async suggestGroups(user: UserDocument): Promise<Group[]> {
    const userMemberships = await this.groupMemberModel
      .find({ user: user._id })
      .select('group');
    const userGroupIds = userMemberships.map((m) => m.group);

    return this.groupModel
      .find({
        interests: { $in: user.interests },
        privacy: 'public',
        _id: { $nin: userGroupIds },
      })
      .populate('owner', 'username avatar')
      .populate('interests')
      .limit(10)
      .exec();
  }

  async findOneById(id: string) {
    const group = await this.groupModel
      .findById(id)
      .populate('owner', 'username avatar')
      .populate('interests')
      .lean()
      .exec();
    if (!group)
      throw new NotFoundException(`Không tìm thấy nhóm với ID: ${id}`);

    const members = await this.groupMemberModel
      .find({ group: id })
      .populate('user', 'username avatar');
    const memberCount = await this.groupMemberModel.countDocuments({
      group: id,
    });

    return { ...group, members, memberCount };
  }

  async kickMember(groupId: string, memberUserId: string) {
    const membership = await this.groupMemberModel.findOne({
      group: groupId,
      user: memberUserId,
    });
    if (!membership)
      throw new NotFoundException('Không tìm thấy thành viên này trong nhóm.');
    if (membership.role === GroupRole.OWNER)
      throw new BadRequestException('Không thể xóa chủ sở hữu nhóm.');

    await membership.deleteOne();
    return { message: 'Đã xóa thành viên khỏi nhóm.' };
  }

  async findGroupsForUser(user: UserDocument): Promise<Group[]> {
    const memberships = await this.groupMemberModel
      .find({ user: user._id })
      .select('group');
    const groupIds = memberships.map((m) => m.group);

    return this.groupModel
      .find({ _id: { $in: groupIds } })
      .populate('owner', 'username avatar')
      .populate('interests')
      .exec();
  }

  async getJoinRequests(groupId: string) {
    return this.joinRequestModel
      .find({ group: groupId, status: 'PENDING' })
      .populate('user', 'username avatar');
  }

  async approveRequest(requestId: string, owner: UserDocument) {
    const request = await this.joinRequestModel
      .findById(requestId)
      .populate('user')
      .populate('group');
    if (!request || request.status !== 'PENDING')
      throw new NotFoundException(
        'Không tìm thấy yêu cầu hoặc yêu cầu đã được xử lý.',
      );

    await new this.groupMemberModel({
      user: (request as any).user._id,
      group: (request as any).group._id,
      role: GroupRole.MEMBER,
    }).save();

    await request.deleteOne();

    this.eventEmitter.emit('notification.create', {
      recipientId: (request as any).user._id.toString(),
      actor: owner,
      type: NotificationType.GROUP_REQUEST_ACCEPTED,
      link: `/groups/${(request as any).group._id}`,
    });

    return { message: 'Đã chấp thuận thành viên.' };
  }

  async rejectRequest(requestId: string, owner: UserDocument) {
    const request = await this.joinRequestModel
      .findById(requestId)
      .populate('user')
      .populate('group');
    if (!request) throw new NotFoundException('Không tìm thấy yêu cầu.');

    await request.deleteOne();

    this.eventEmitter.emit('notification.create', {
      recipientId: (request as any).user._id.toString(),
      actor: owner,
      type: NotificationType.GROUP_REQUEST_REJECTED,
      link: null,
    });

    return { message: 'Đã từ chối yêu cầu.' };
  }

  async addXpToMember(
    userId: string,
    groupId: string,
    xpAmount: number,
  ): Promise<void> {
    await this.groupMemberModel.findOneAndUpdate(
      { user: userId, group: groupId },
      { $inc: { xp: xpAmount } },
    );
  }

  async deleteGroup(
    groupId: string,
    user: UserDocument,
  ): Promise<{ message: string }> {
    const group = await this.groupModel.findById(groupId);
    if (!group) {
      throw new NotFoundException('Không tìm thấy nhóm.');
    }

    const userRole = (user as any).globalRole;

    if (
      group.owner.toString() !== user._id.toString() &&
      userRole !== GlobalRole.ADMIN
    ) {
      throw new UnauthorizedException('Bạn không có quyền xóa nhóm này.');
    }

    // Xóa các dữ liệu liên quan
    const postsInGroup = await this.postModel
      .find({ group: groupId })
      .select('_id')
      .exec();
    const postIds = postsInGroup.map((p) => p._id);

    if (postIds.length > 0) {
      await this.commentModel.deleteMany({ post: { $in: postIds } });
    }

    await this.postModel.deleteMany({ group: groupId });
    await this.groupMemberModel.deleteMany({ group: groupId });
    await group.deleteOne();

    return { message: 'Đã xóa nhóm và tất cả dữ liệu liên quan thành công.' };
  }

  // ✅ Lấy danh sách thành viên
  async getGroupMembers(groupId: string): Promise<GroupMember[]> {
    return this.groupMemberModel
      .find({ group: groupId })
      .populate('user', 'username avatar');
  }

  async getJoinStatus(user: UserDocument, groupId: string) {
    const membership = await this.groupMemberModel.findOne({
      user: user._id,
      group: groupId,
    });
    if (membership) return { status: 'MEMBER' };

    const joinRequest = await this.joinRequestModel.findOne({
      user: user._id,
      group: groupId,
      status: 'PENDING',
    });
    if (joinRequest) return { status: 'PENDING' };

    return { status: 'NONE' };
  }


   // ✅ HÀM MỜI NGƯỜI DÙNG ĐÃ ĐƯỢC CẬP NHẬT HOÀN CHỈNH
  async inviteUser(
    groupId: string,
    inviter: UserDocument,
    inviteeId: string,
  ): Promise<{ message: string }> {
    const group = await this.groupModel.findById(groupId);
    if (!group) {
      throw new NotFoundException('Không tìm thấy nhóm.');
    }

    const invitee = await this.userModel.findById(inviteeId);
    if (!invitee) {
      throw new NotFoundException('Không tìm thấy người dùng bạn muốn mời.');
    }

    // Kiểm tra xem người được mời đã ở trong nhóm chưa
    const isAlreadyMember = await this.groupMemberModel.findOne({
      user: inviteeId,
      group: groupId,
    });
    if (isAlreadyMember) {
      throw new ConflictException('Người này đã là thành viên của nhóm.');
    }

    // Xử lý cho NHÓM CÔNG KHAI
    if (group.privacy === 'public') {
      // Thêm thẳng người dùng vào nhóm
      await new this.groupMemberModel({
        user: inviteeId,
        group: groupId,
        role: GroupRole.MEMBER,
      }).save();

      // Gửi thông báo cho người được mời
      this.eventEmitter.emit('notification.create', {
        recipientId: inviteeId,
        actor: inviter,
        type: NotificationType.GROUP_INVITE, // Loại thông báo mới
        // type: NotificationType.GROUP_INVITE_ACCEPTED, // Loại thông báo mới
        link: `/groups/${group._id}`,
        message: `${inviter.username} đã thêm bạn vào nhóm "${group.name}".`,
      });

      return { message: `Đã thêm ${invitee.username} vào nhóm.` };
    }

    // Xử lý cho NHÓM RIÊNG TƯ
    // Kiểm tra xem đã có yêu cầu tham gia đang chờ xử lý chưa
    const existingRequest = await this.joinRequestModel.findOne({
      user: inviteeId,
      group: groupId,
    });
    if (existingRequest) {
      throw new ConflictException('Bạn đã gửi một lời mời cho người này rồi, đang chờ phê duyệt.');
    }

    // Tạo một yêu cầu tham gia mới
    await new this.joinRequestModel({
      user: inviteeId,
      group: groupId,
    }).save();

    // Gửi thông báo cho chủ sở hữu nhóm
    this.eventEmitter.emit('notification.create', {
      recipientId: group.owner.toString(),
      actor: inviter,
      type: NotificationType.GROUP_INVITE, // Loại thông báo mới
      link: `/groups/${group._id}/manage?tab=requests`, // Dẫn đến tab yêu cầu
      message: `${inviter.username} đã mời ${invitee.username} tham gia nhóm "${group.name}".`,
    });

    return { message: 'Đã gửi lời mời. Yêu cầu cần được phê duyệt.' };
  }
}
