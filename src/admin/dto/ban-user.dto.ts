import { IsNotEmpty, IsString } from 'class-validator';

export class BanUserDto {
  @IsNotEmpty()
  @IsString()
  reason: string;
}