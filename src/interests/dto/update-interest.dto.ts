import { IsNotEmpty, IsString } from 'class-validator';

export class UpdateInterestDto {
  @IsNotEmpty()
  @IsString()
  name: string;
}