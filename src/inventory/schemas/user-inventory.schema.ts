import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';
import { User } from '../../auth/schemas/user.schema';
import { ShopItem } from '../../shop/schemas/shop-item.schema';

@Schema({ timestamps: true })
export class UserInventory {
  @Prop({ required: true, type: Types.ObjectId, ref: User.name })
  user: Types.ObjectId;

  @Prop({ required: true, type: Types.ObjectId, ref: ShopItem.name })
  item: Types.ObjectId;
}

export type UserInventoryDocument = UserInventory & Document;

export const UserInventorySchema = SchemaFactory.createForClass(UserInventory);

// Unique index: 1 user không thể sở hữu 1 item 2 lần
UserInventorySchema.index({ user: 1, item: 1 }, { unique: true });
