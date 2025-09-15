import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { User } from '../../auth/schemas/user.schema';
import { Chatroom } from './chatroom.schema';

export type MessageDocument = Message & Document;

@Schema({ timestamps: true })
export class Message {
  @Prop({ required: true, type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  sender: User;

  @Prop({
    required: true,
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Chatroom',
  })
  chatroom: Chatroom;

  @Prop({ required: true, trim: true })
  content: string;

  @Prop({ type: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }] })
  readBy: User[]; // Mảng chứa ID của những người đã đọc
}

export const MessageSchema = SchemaFactory.createForClass(Message);

//indexes giúp paginate theo phòng mượt, và tìm theo readBy
MessageSchema.index({ chatroom: 1, createdAt: 1 });   
MessageSchema.index({ readBy: 1 });                   
