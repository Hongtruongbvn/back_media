import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document, Types } from 'mongoose';
import { User } from '../../auth/schemas/user.schema';
import { Message } from './message.schema';

export type ChatroomDocument = Chatroom & Document;

@Schema({ _id: false })
class ChatMemberInfo {
  // ⚠️ TypeScript type phải là ObjectId (khi populate sẽ là User, nhưng DB lưu OID)
  @Prop({ required: true, type: mongoose.Schema.Types.ObjectId, ref: User.name })
  user: Types.ObjectId; // <- CHỈNH Ở ĐÂY

  @Prop({ default: 0 })
  unreadCount: number;
}
const ChatMemberInfoSchema = SchemaFactory.createForClass(ChatMemberInfo);

@Schema({ timestamps: true })
export class Chatroom {
  @Prop({ trim: true })
  name?: string;

  // đường dẫn tương đối tới ảnh nhóm
  @Prop()
  avatar?: string;

  // người tạo nhóm: cũng là ObjectId
  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: User.name })
  createdBy?: Types.ObjectId;

  // admin nhóm: mảng ObjectId
  @Prop({ type: [{ type: mongoose.Schema.Types.ObjectId, ref: User.name }], default: [] })
  admins: Types.ObjectId[];

  // danh sách thành viên: mảng subdocument
  @Prop({ required: true, type: [ChatMemberInfoSchema] })
  members: ChatMemberInfo[];

  @Prop({ default: false })
  isGroupChat: boolean;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'Message' })
  lastMessage?: Message;
}
export const ChatroomSchema = SchemaFactory.createForClass(Chatroom);

ChatroomSchema.index({ 'members.user': 1 });
ChatroomSchema.index({ updatedAt: -1 });
