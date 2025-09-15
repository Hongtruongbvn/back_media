import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { User } from '../../auth/schemas/user.schema';
import { Group } from './group.schema';

export type GroupMemberDocument = GroupMember & Document;

export enum GroupRole {
  OWNER = 'OWNER',
  ADMIN = 'ADMIN',
  MEMBER = 'MEMBER',
}

@Schema({ timestamps: true })
export class GroupMember {
  @Prop({ required: true, type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  user: User;

  @Prop({ required: true, type: mongoose.Schema.Types.ObjectId, ref: 'Group' })
  group: Group;

  @Prop({ required: true, enum: GroupRole, default: GroupRole.MEMBER })
  role: GroupRole;

  @Prop({ default: 0 })
  xp: number;
  
  @Prop({ default: 1 })
  level: number;
}

export const GroupMemberSchema = SchemaFactory.createForClass(GroupMember);
