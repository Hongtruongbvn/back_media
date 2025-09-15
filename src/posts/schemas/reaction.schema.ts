import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose from 'mongoose';
import { User } from '../../auth/schemas/user.schema';

// Định nghĩa các loại cảm xúc hợp lệ
export enum ReactionType {
  LIKE = 'LIKE',
  LOVE = 'LOVE',
  HAHA = 'HAHA',
  WOW = 'WOW',
  SAD = 'SAD',
  ANGRY = 'ANGRY',
}

@Schema({ _id: false }) // Không cần _id riêng cho sub-document
export class Reaction {
  @Prop({ required: true, type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  user: User;

  @Prop({ required: true, enum: ReactionType })
  type: ReactionType;
}

export const ReactionSchema = SchemaFactory.createForClass(Reaction);