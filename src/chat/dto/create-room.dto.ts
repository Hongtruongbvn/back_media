// dto/create-room.dto.ts
import {
  IsArray, ArrayNotEmpty, IsMongoId, IsOptional, IsString, MaxLength
} from 'class-validator';
import { Transform } from 'class-transformer';

export class CreateRoomDto {
  @Transform(({ value }) => {
    // FormData có thể gửi 1 giá trị hoặc nhiều giá trị trùng key
    if (Array.isArray(value)) return value;
    if (typeof value === 'string' && value.trim().startsWith('[')) {
      try { return JSON.parse(value); } catch { /* ignore */ }
    }
    return value ? [String(value)] : [];
  })
  @IsArray()
  @ArrayNotEmpty()
  @IsMongoId({ each: true })
  memberIds!: string[];

  @IsOptional()
  @IsString()
  @MaxLength(120)
  name?: string;
}
