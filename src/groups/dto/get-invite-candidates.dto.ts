import { IsOptional, IsString, MaxLength } from 'class-validator';

export class GetInviteCandidatesDto {
  @IsOptional()
  @IsString()
  @MaxLength(64)
  search?: string;
}
