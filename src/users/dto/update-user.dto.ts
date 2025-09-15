// apps/api/src/users/dto/update-user.dto.ts
import { IsOptional, IsString, IsDateString, IsArray, ArrayMinSize, IsBoolean } from 'class-validator';

export class UpdateUserDto {
  @IsOptional()
  @IsString()
  avatar?: string;

  @IsOptional()
  @IsString()
  coverImage?: string;

  @IsOptional()
  @IsString()
  bio?: string;

  @IsOptional()
  @IsDateString()
  birthday?: Date;

  @IsOptional()
  @IsString()
  username?: string;

    // ❗️ THÊM CÁC DÒNG NÀY VÀO
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  @ArrayMinSize(1)
  interests?: string[];

  @IsOptional()
  @IsBoolean()
  hasSelectedInterests?: boolean;
}
