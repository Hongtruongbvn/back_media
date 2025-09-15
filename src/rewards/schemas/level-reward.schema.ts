import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { ShopItem } from '../../shop/schemas/shop-item.schema';

@Schema({ timestamps: true })
export class LevelReward {
  @Prop({ required: true }) level: number;
  @Prop({ required: true, type: mongoose.Schema.Types.ObjectId, ref: 'ShopItem' }) rewardItem: ShopItem;
  @Prop() description?: string;
}
export const LevelRewardSchema = SchemaFactory.createForClass(LevelReward);
export type LevelRewardDocument = LevelReward & Document;