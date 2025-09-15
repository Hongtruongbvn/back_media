import {
  Injectable,
  UnauthorizedException,
  ForbiddenException,
  Inject,
  forwardRef,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { Chatroom, ChatroomDocument } from './schemas/chatroom.schema';
import { Message, MessageDocument } from './schemas/message.schema';
import { User, UserDocument } from '../auth/schemas/user.schema';
import { JwtService } from '@nestjs/jwt';
import { ChatGateway } from './chat.gateway';

@Injectable()
export class ChatService {
  constructor(
    @InjectModel(Chatroom.name) private chatroomModel: Model<ChatroomDocument>,
    @InjectModel(Message.name) private messageModel: Model<MessageDocument>,
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private jwtService: JwtService,
    @Inject(forwardRef(() => ChatGateway))
    private readonly chatGateway: ChatGateway,
  ) {}

  private toObjectId(id: string | Types.ObjectId | UserDocument | any): Types.ObjectId {
    if (!id) throw new Error('Invalid id');
    if (id instanceof Types.ObjectId) return id;
    if (typeof id === 'string') return new Types.ObjectId(id);
    if (typeof id === 'object' && id._id) {
      const inner = id._id;
      if (inner instanceof Types.ObjectId) return inner;
      return new Types.ObjectId(String(inner));
    }
    return new Types.ObjectId(String(id));
  }

  async getUserFromSocket(token: string): Promise<UserDocument> {
    let payload: any;
    try {
      payload = this.jwtService.verify(token);
    } catch {
      throw new UnauthorizedException();
    }
    if (!payload.sub) throw new UnauthorizedException();
    const user = await this.userModel.findById(payload.sub);
    if (!user) throw new UnauthorizedException();
    return user;
  }

  getUserById(id: string) {
    return this.userModel.findById(id);
  }

  async isMemberOfRoom(userId: string | Types.ObjectId, roomId: string) {
    const uid = this.toObjectId(userId as any);
    const rid = this.toObjectId(roomId as any);
    const count = await this.chatroomModel.countDocuments({ _id: rid, 'members.user': uid });
    return count > 0;
  }

  private async isBlockedBetween(
    userAId: string | Types.ObjectId | UserDocument | any,
    userBId: string | Types.ObjectId | UserDocument | any
  ): Promise<boolean> {
    const A = this.toObjectId(userAId);
    const B = this.toObjectId(userBId);
    const [a, b] = await Promise.all([
      this.userModel.findById(A).select('_id blockedUsers').lean(),
      this.userModel.findById(B).select('_id blockedUsers').lean()
    ]);
    if (!a || !b) return false;
    const aBlockedB = Array.isArray((a as any).blockedUsers) && (a as any).blockedUsers.some((id: any) => id.toString() === B.toString());
    const bBlockedA = Array.isArray((b as any).blockedUsers) && (b as any).blockedUsers.some((id: any) => id.toString() === A.toString());
    return aBlockedB || bBlockedA;
  }

  async createChatroom(
    creator: UserDocument,
    memberIds: string[],
    name?: string,
    avatar?: Express.Multer.File,
  ): Promise<Chatroom> {
    const uniqueIds = Array.from(new Set([creator._id.toString(), ...memberIds.map(String)]))
      .map(id => new Types.ObjectId(id));

    const isGroup = uniqueIds.length > 2;

    // DM: chặn nếu block lẫn nhau & mở lại phòng cũ nếu đã có
    if (!isGroup && uniqueIds.length === 2) {
      const [u1, u2] = uniqueIds;
      if (await this.isBlockedBetween(u1, u2)) {
        throw new ForbiddenException('Cannot create/open a DM due to blocking');
      }
      const existing = await this.chatroomModel.findOne({
        isGroupChat: false,
        'members.user': { $all: [u1, u2] },
        $expr: { $eq: [{ $size: '$members' }, 2] },
      });
      if (existing) return existing;
    }

    const members = uniqueIds.map(id => ({ user: id, unreadCount: 0 }));

    let avatarPath: string | undefined;
    if (avatar?.filename) {
      avatarPath = `/uploads/groups/${avatar.filename}`;
    } else if ((avatar as any)?.path) {
      const p = String((avatar as any).path).replace(/\\/g, '/');
      const idx = p.lastIndexOf('/uploads/');
      avatarPath = idx >= 0 ? p.slice(idx) : undefined;
    }

    const newRoom = await this.chatroomModel.create({
      name: name?.trim() || undefined,
      avatar: isGroup ? avatarPath : undefined,
      members,
      isGroupChat: isGroup,
      createdBy: isGroup ? creator._id : undefined,
      admins: isGroup ? [creator._id] : [],
    });

    const populated = await this.chatroomModel
      .findById(newRoom._id)
      .populate('members.user', 'username avatar')
      .populate('lastMessage')
      .lean();

    this.chatGateway.broadcastRoomCreated?.(populated);
    return populated as any;
  }

  // ----------------- ĐỔI AVATAR NHÓM -----------------
  async updateGroupAvatar(acting: UserDocument, chatroomId: string, avatar?: Express.Multer.File) {
    if (!avatar) throw new BadRequestException('No avatar file uploaded');

    const room = await this.chatroomModel.findById(chatroomId);
    if (!room) throw new NotFoundException('Room not found');
    if (!room.isGroupChat) throw new BadRequestException('Not a group chat');

    const isCreator = room.createdBy && room.createdBy.toString() === acting._id.toString();
    const isAdmin = room.admins?.some(a => a.toString() === acting._id.toString());
    if (!isCreator && !isAdmin) throw new ForbiddenException('Only creator/admin can update group avatar');

    const avatarPath = `/uploads/groups/${avatar.filename}`;
    room.avatar = avatarPath;
    await room.save();

    const populated = await this.chatroomModel
      .findById(room._id)
      .populate('members.user', 'username avatar')
      .populate('lastMessage')
      .lean();

    this.chatGateway.server?.to(String(room._id)).emit('room_updated', populated);
    this.chatGateway.broadcastRoomCreated?.(populated);
    return populated;
  }

  // ----------------- THÊM THÀNH VIÊN -----------------
  async addMembersToGroup(acting: UserDocument, chatroomId: string, memberIds: string[]) {
    if (!Array.isArray(memberIds) || memberIds.length === 0) {
      throw new BadRequestException('memberIds is required');
    }
    const room = await this.chatroomModel.findById(chatroomId);
    if (!room) throw new NotFoundException('Room not found');
    if (!room.isGroupChat) throw new BadRequestException('Not a group chat');

    const isCreator = room.createdBy && room.createdBy.toString() === acting._id.toString();
    const isAdmin = room.admins?.some(a => a.toString() === acting._id.toString());
    if (!isCreator && !isAdmin) throw new ForbiddenException('Only creator/admin can add members');

    const existingIds = new Set(room.members.map(m => m.user.toString()));
    const toAdd = Array.from(new Set(memberIds.map(String))).filter(id => !existingIds.has(id));

    if (toAdd.length === 0) {
      const populatedNoChange = await this.chatroomModel
        .findById(room._id)
        .populate('members.user', 'username avatar')
        .populate('lastMessage')
        .lean();
      return populatedNoChange;
    }

    toAdd.forEach(id => room.members.push({ user: new Types.ObjectId(id), unreadCount: 0 }));
    await room.save();

    const populated = await this.chatroomModel
      .findById(room._id)
      .populate('members.user', 'username avatar')
      .populate('lastMessage')
      .lean();

    this.chatGateway.server?.to(String(room._id)).emit('room_members_added', {
      chatroomId: room._id,
      memberIds: toAdd,
      room: populated,
    });
    this.chatGateway.broadcastRoomCreated?.(populated);
    return populated;
  }

  // ----------------- KICK THÀNH VIÊN -----------------
  async removeMemberFromGroup(acting: UserDocument, chatroomId: string, targetUserId: string) {
    const room = await this.chatroomModel.findById(chatroomId);
    if (!room) throw new NotFoundException('Room not found');
    if (!room.isGroupChat) throw new BadRequestException('Not a group chat');

    const isCreator = room.createdBy && room.createdBy.toString() === acting._id.toString();
    if (!isCreator) throw new ForbiddenException('Only creator can remove members');

    if (targetUserId === acting._id.toString()) {
      throw new BadRequestException('Creator cannot kick themselves');
    }
    if (room.createdBy?.toString() === targetUserId) {
      throw new BadRequestException('Cannot remove the creator');
    }

    const before = room.members.length;
    room.members = room.members.filter(m => m.user.toString() !== targetUserId);
    if (room.members.length === before) {
      throw new NotFoundException('User is not a member of this room');
    }
    room.admins = (room.admins || []).filter(a => a.toString() !== targetUserId);
    await room.save();

    const populated = await this.chatroomModel
      .findById(room._id)
      .populate('members.user', 'username avatar')
      .populate('lastMessage')
      .lean();

    this.chatGateway.server?.to(String(room._id)).emit('room_member_removed', {
      chatroomId: room._id,
      userId: targetUserId,
      room: populated,
    });
    this.chatGateway.broadcastRoomCreated?.(populated);
    return populated;
  }

  // ----------------- RỜI NHÓM (member tự rời) -----------------
  async leaveRoom(acting: UserDocument | string, chatroomId: string) {
    const uid = typeof acting === 'string' ? this.toObjectId(acting) : this.toObjectId(acting._id);
    const room = await this.chatroomModel.findById(chatroomId);
    if (!room) throw new NotFoundException('Room not found');

    const idx = room.members.findIndex(m => m.user.toString() === uid.toString());
    if (idx === -1) throw new ForbiddenException('You are not a member of this room');

    // Bỏ mình khỏi members
    room.members.splice(idx, 1);

    // Nếu phòng trống → xoá
    if (room.members.length === 0) {
      await room.deleteOne();
      this.chatGateway.server?.emit('room_member_removed', { room: { _id: chatroomId, members: [] } });
      return { ok: true, deleted: true };
    }

    // Nếu là DM và còn <2 người → xoá phòng
    if (!room.isGroupChat && room.members.length < 2) {
      await room.deleteOne();
      this.chatGateway.server?.emit('room_member_removed', { room: { _id: chatroomId, members: [] } });
      return { ok: true, deleted: true };
    }

    // Nếu là owner → chuyển owner
    const wasOwner = room.createdBy && room.createdBy.toString() === uid.toString();
    if (wasOwner) {
      // ưu tiên admin còn lại
      const nextAdmin = (room.admins || []).find(a => a.toString() !== uid.toString());
      if (nextAdmin) {
        room.createdBy = nextAdmin as any;
      } else {
        const nextMember = room.members[0]?.user;
        if (nextMember) room.createdBy = nextMember as any;
      }
      // bảo đảm owner nằm trong danh sách admins
      if (room.createdBy && !(room.admins || []).some(a => a.toString() === room.createdBy!.toString())) {
        room.admins = [...(room.admins || []), room.createdBy as any];
      }
    }

    // loại mình khỏi admins (nếu có)
    room.admins = (room.admins || []).filter(a => a.toString() !== uid.toString());
    await room.save();

    const populated = await this.chatroomModel
      .findById(room._id)
      .populate('members.user', 'username avatar')
      .populate('lastMessage')
      .lean();

    // Thông báo tới clients
    this.chatGateway.server?.to(String(room._id)).emit('room_member_removed', {
      chatroomId: room._id,
      userId: uid.toString(),
      room: populated,
    });
    this.chatGateway.broadcastRoomCreated?.(populated);
    this.chatGateway.server?.emit('room_updated', populated);

    return { ok: true, room: populated };
  }

  // ---------- XÓA NHÓM (chỉ creator) ----------
  async deleteRoomAsOwner(acting: UserDocument, chatroomId: string) {
    const room = await this.chatroomModel.findById(chatroomId);
    if (!room) throw new NotFoundException('Room not found');
    if (!room.isGroupChat) throw new BadRequestException('Not a group chat');

    const isCreator = room.createdBy && room.createdBy.toString() === acting._id.toString();
    if (!isCreator) throw new ForbiddenException('Only creator can delete this group');

    const memberIds = room.members.map(m => String(m.user));

    // Xoá toàn bộ tin nhắn của phòng (tuỳ nghiệp vụ)
    await this.messageModel.deleteMany({ chatroom: room._id });

    // Thông báo tới thành viên trong room trước khi xoá
    this.chatGateway.server?.to(String(room._id)).emit('room_deleted', {
      chatroomId: String(room._id),
      memberIds,
    });

    await room.deleteOne();

    // Phát rộng (để list ngoài room cũng cập nhật)
    this.chatGateway.server?.emit('room_deleted', {
      chatroomId: String(chatroomId),
      memberIds,
    });

    return { ok: true, deleted: true, chatroomId: String(chatroomId) };
  }

  // ------- message / mark read / list rooms -------
  async createMessage(sender: UserDocument, chatroomId: string, content: string) {
    const rid = this.toObjectId(chatroomId);
    const sid = this.toObjectId(sender._id);
    const text = (content ?? '').trim();
    if (!text) throw new BadRequestException('Message content is empty');

    const isMember = await this.isMemberOfRoom(sid.toString(), rid.toString());
    if (!isMember) throw new UnauthorizedException();

    const existingMessage = await this.messageModel.findOne({
      sender: sid,
      chatroom: rid,
      content: text,
      createdAt: { $gt: new Date(Date.now() - 60000) },
    });

    if (existingMessage) {
      throw new BadRequestException('Duplicate message detected. Please wait a moment before sending again.');
    }

    const saved = await new this.messageModel({
      sender: sid,
      chatroom: rid,
      content: text,
      readBy: [sid],
    }).save();

    await this.chatroomModel.updateOne(
      { _id: rid },
      {
        $set: { lastMessage: saved._id, updatedAt: new Date() },
        $inc: { 'members.$[other].unreadCount': 1 },
      },
      { arrayFilters: [{ 'other.user': { $ne: sid } }] },
    );

    const populated = await saved.populate('sender', 'username avatar');
    this.chatGateway.server?.to(String(rid)).emit('newMessage', populated);
    return populated;
  }

  async markRoomAsRead(userId: string | Types.ObjectId, chatroomId: string) {
    const uid = this.toObjectId(userId);
    const rid = this.toObjectId(chatroomId);
    await this.chatroomModel.updateOne(
      { _id: rid, 'members.user': uid },
      { $set: { 'members.$.unreadCount': 0 } },
    );
    await this.messageModel.updateMany(
      { chatroom: rid, readBy: { $ne: uid } },
      { $addToSet: { readBy: uid } },
    );
  }

  async findRoomById(id: string): Promise<ChatroomDocument | null> {
    return this.chatroomModel.findById(id).exec();
  }

  async createBotMessage(senderId: string, chatroomId: string, content: string) {
    const message = new this.messageModel({ sender: senderId, chatroom: chatroomId, content });
    return (await message.save()).populate('sender', 'username avatar');
  }

  async findRoomsForUser(user: UserDocument): Promise<Chatroom[]> {
    return this.chatroomModel
      .find({ 'members.user': user._id })
      .populate('members.user', 'username avatar')
      .populate('lastMessage')
      .sort({ updatedAt: -1 })
      .exec();
  }

  async findMessagesInRoomForUser(userId: string | Types.ObjectId, chatroomId: string): Promise<Message[]> {
    const ok = await this.isMemberOfRoom(userId, chatroomId);
    if (!ok) throw new UnauthorizedException();
    return this.messageModel
      .find({ chatroom: chatroomId })
      .populate('sender', 'username avatar')
      .sort({ createdAt: 'asc' })
      .exec();
  }
}
