import { IsNotEmpty, IsString } from 'class-validator';

export class WarnUserDto {
  @IsNotEmpty()
  @IsString()
  reason: string;
}
