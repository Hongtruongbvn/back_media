import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';


@Schema()
export class User {

  @Prop({ required: true, unique: true })
  username: string;        

  @Prop()
  bio: string;

  @Prop()
  avatar: string;

  @Prop()
  coverImage: string;

  @Prop()
  birthday: Date;

  @Prop({ type: [String], default: [] })
  purchasedItems: string[];

  @Prop({ type: String, default: null })
  activeItem: string | null;

  @Prop({ type: Types.ObjectId, ref: 'ShopItem' })
  equippedAvatarFrame?: Types.ObjectId;
}

export type UserDocument = User & Document;
export const UserSchema = SchemaFactory.createForClass(User);
