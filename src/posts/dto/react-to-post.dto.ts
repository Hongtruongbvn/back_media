import { IsEnum, IsNotEmpty } from 'class-validator';
import { ReactionType } from '../schemas/reaction.schema';

export class ReactToPostDto {
  @IsNotEmpty()
  @IsEnum(ReactionType)
  type: ReactionType;
}