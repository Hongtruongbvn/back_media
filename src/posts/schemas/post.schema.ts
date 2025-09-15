import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { User } from '../../auth/schemas/user.schema';
import { Group } from '../../groups/schemas/group.schema';
import { Reaction, ReactionSchema } from './reaction.schema';

export type PostDocument = Post & Document;

export enum ModerationStatus {
  PENDING = 'PENDING',
  APPROVED = 'APPROVED',
  REJECTED = 'REJECTED',
  PROCESSING = 'PROCESSING',
}

export enum PostVisibility {
  PUBLIC = 'PUBLIC',
  FRIENDS_ONLY = 'FRIENDS_ONLY',
  PRIVATE = 'PRIVATE',
}

export enum ReactionType {
  LIKE = 'LIKE',
  LOVE = 'LOVE',
  HAHA = 'HAHA',
  WOW = 'WOW',
  SAD = 'SAD',
  ANGRY = 'ANGRY',
}
@Schema({ timestamps: true })
export class Post {
  @Prop({ enum: ModerationStatus, default: ModerationStatus.PENDING })
  moderationStatus: ModerationStatus;

  @Prop({ required: true, type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  author: User;

  @Prop({ required: false, trim: true })
  content: string;

  @Prop([String])
  mediaUrls: string[];

  @Prop({ type: [ReactionSchema], default: [] })
  reactions: Reaction[];

  @Prop({ default: 0 })
  commentCount: number;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'Group', required: false })
  group?: Group;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: false })
  repostOf?: Post;

  @Prop({ default: 0 })
  repostCount: number;

  @Prop({ enum: PostVisibility, default: PostVisibility.PUBLIC })
  visibility: PostVisibility;
}

export const PostSchema = SchemaFactory.createForClass(Post);
