import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { User } from '../../auth/schemas/user.schema';

export type FriendRequestDocument = FriendRequest & Document;

export enum FriendRequestStatus {
  PENDING = 'PENDING',
  ACCEPTED = 'ACCEPTED',
  REJECTED = 'REJECTED',
}

@Schema({ timestamps: true })
export class FriendRequest {
  @Prop({ required: true, type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  sender: User; // Người gửi yêu cầu

  @Prop({ required: true, type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  recipient: User; // Người nhận yêu cầu

  @Prop({
    required: true,
    enum: FriendRequestStatus,
    default: FriendRequestStatus.PENDING,
  })
  status: FriendRequestStatus;
}

export const FriendRequestSchema = SchemaFactory.createForClass(FriendRequest);
