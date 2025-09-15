import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';
import mongoose, { Types } from 'mongoose';

@Schema({ timestamps: true, collection: 'blocks' })
export class Block {
  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true })
  blocker!: Types.ObjectId; // người chặn

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true })
  blocked!: Types.ObjectId; // bị chặn
}

export type BlockDocument = HydratedDocument<Block>;
export const BlockSchema = SchemaFactory.createForClass(Block);

// chặn 1 lần duy nhất
BlockSchema.index({ blocker: 1, blocked: 1 }, { unique: true });
