import { IsNotEmpty, IsString, IsNumber, Min } from 'class-validator';

export class SuspendUserDto {
  @IsNotEmpty()
  @IsString()
  reason: string;

  @IsNumber()
  @Min(1)
  durationInDays: number;
}