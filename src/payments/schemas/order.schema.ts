import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { User } from '../../auth/schemas/user.schema';
import { CoinPackage } from './coin-package.schema'; // <-- THAY ĐỔI

export enum OrderStatus {
  PENDING = 'PENDING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
}

@Schema({ timestamps: true })
export class Order {
  @Prop({ required: true, type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  user: User;

  // --- THAY ĐỔI TỪ `item` SANG `coinPackage` ---
  @Prop({
    required: true,
    type: mongoose.Schema.Types.ObjectId,
    ref: 'CoinPackage',
  })
  coinPackage: CoinPackage;

  @Prop({ required: true }) 
  amount: number; // Giá tiền thật

  @Prop({ required: true, enum: OrderStatus, default: OrderStatus.PENDING })
  status: OrderStatus;

    @Prop({ index: true })
  paymentIntentId?: string; // Lưu ID từ cổng thanh toán (Stripe)
}
export const OrderSchema = SchemaFactory.createForClass(Order);
export type OrderDocument = Order & Document;
