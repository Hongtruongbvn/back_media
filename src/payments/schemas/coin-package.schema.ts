import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type CoinPackageDocument = CoinPackage & Document;

@Schema({ timestamps: true })
export class CoinPackage {
  @Prop({ required: true, unique: true })
  packageId: string; // Ví dụ: 'pack_100_coins'

  @Prop({ required: true })
  name: string; // Ví dụ: 'Gói 100 Coins'

  @Prop({ required: true })
  coinsAmount: number;

  @Prop({ required: true })
  price: number; // Giá bằng tiền thật

  @Prop({ required: true, default: 'VND' })
  currency: string;
}

export const CoinPackageSchema = SchemaFactory.createForClass(CoinPackage);