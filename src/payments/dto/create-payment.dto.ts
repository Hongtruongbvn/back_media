import { IsNotEmpty, IsString } from 'class-validator';

export class CreatePaymentDto {
  @IsNotEmpty()
  @IsString()
  packageId: string; // ID của gói coin người dùng muốn mua
}
