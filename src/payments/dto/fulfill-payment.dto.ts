// File: src/payments/dto/fulfill-payment.dto.ts
import { IsNotEmpty, IsString } from 'class-validator';

export class FulfillPaymentDto {
  @IsString()
  @IsNotEmpty()
  paymentIntentId: string;
}
