import { IsEnum, IsOptional, IsString } from 'class-validator';
import { PostVisibility } from '../schemas/post.schema';

export class RepostDto {
  @IsOptional()
  @IsString()
  content?: string;

  @IsOptional()
  @IsEnum(PostVisibility)
  visibility?: PostVisibility;
}
