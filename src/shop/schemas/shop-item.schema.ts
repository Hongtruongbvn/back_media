import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Types } from 'mongoose';

export enum ItemType {
  AVATAR_FRAME = 'AVATAR_FRAME',
  PROFILE_BACKGROUND = 'PROFILE_BACKGROUND',
  PROFILE_EFFECT = 'PROFILE_EFFECT',
  AVATAR_DECORATION = 'AVATAR_DECORATION',
  NAMEPLATE_THEME = 'NAMEPLATE_THEME',
}

@Schema({ timestamps: true })
export class ShopItem {
  _id!: Types.ObjectId;              

  @Prop({ required: true, trim: true }) name!: string;
  @Prop({ required: true }) description!: string;
  @Prop({ required: true, enum: ItemType }) type!: ItemType;

  @Prop({ required: true }) price!: number;  // coins
  @Prop() assetUrl?: string;
}

export type ShopItemDocument = HydratedDocument<ShopItem>; // <<-- dùng HydratedDocument thay vì Document
export const ShopItemSchema = SchemaFactory.createForClass(ShopItem);
