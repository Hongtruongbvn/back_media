import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { User } from '../../auth/schemas/user.schema';

export type StoryDocument = Story & Document;

@Schema({ timestamps: true })
export class Story {
  @Prop({ required: true, type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  author: User;
  @Prop({ required: true })
  mediaUrl: string;
  @Prop({ required: true, enum: ['IMAGE', 'VIDEO'] })
  mediaType: string;
}
export const StorySchema = SchemaFactory.createForClass(Story);
StorySchema.index({ createdAt: 1 }, { expireAfterSeconds: 86400 });