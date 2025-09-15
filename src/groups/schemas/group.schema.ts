import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
// Tên file user schema của bạn là user.schema.ts trong thư mục auth
import { User } from '../../auth/schemas/user.schema'; 
import { Interest } from '../../interests/schemas/interest.schema';

export type GroupDocument = Group & Document;

// --- Định nghĩa cấu trúc cho một thành viên trong nhóm ---
// Đây là phần quan trọng nhất để sửa lỗi StrictPopulateError
@Schema({ _id: false }) // Không cần _id riêng cho sub-document này
class GroupMember {
  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true })
  user: User; // Tham chiếu đến model User

  @Prop({ type: String, enum: ['MEMBER', 'MODERATOR', 'OWNER'], default: 'MEMBER' })
  role: string;

  @Prop({ default: Date.now })
  joinedAt: Date;
}


// --- Schema chính cho Group ---
@Schema({ timestamps: true })
export class Group {
  _id: mongoose.Schema.Types.ObjectId;
  @Prop({ required: true, trim: true })
  name: string;

  @Prop({ default: '' })
  description: string;

  @Prop({ required: true, type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  owner: User;

  @Prop({ type: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Interest' }] })
  interests: Interest[];

  // ✅ [ĐÃ SỬA] Bổ sung các trường còn thiếu
  
  @Prop({ type: String, enum: ['public', 'private'], default: 'public' })
  privacy: string;

  @Prop({ type: String })
  avatar?: string;

  @Prop({ type: String })
  coverImage?: string;

  // ✅ [ĐÃ SỬA] Thêm trường 'members' với cấu trúc đã định nghĩa ở trên
  @Prop({ type: [GroupMember], default: [] })
  members: GroupMember[];
}

export const GroupSchema = SchemaFactory.createForClass(Group);

// Thêm một trường ảo để có thể lấy memberCount một cách tiện lợi
GroupSchema.virtual('memberCount').get(function(this: GroupDocument) {
  return this.members.length;
});