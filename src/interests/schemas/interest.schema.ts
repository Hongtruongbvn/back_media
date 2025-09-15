import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type InterestDocument = Interest & Document;

@Schema()
export class Interest {
  @Prop({ required: true, unique: true, trim: true })
  name: string;
}

export const InterestSchema = SchemaFactory.createForClass(Interest);