import { IsEnum, IsNotEmpty, IsOptional, IsString } from 'class-validator';
import { PostVisibility } from '../schemas/post.schema';

export class UpdatePostDto {
  @IsOptional()
  @IsString()
  content?: string;

  @IsOptional()
  @IsEnum(PostVisibility)
  visibility?: PostVisibility;
}
