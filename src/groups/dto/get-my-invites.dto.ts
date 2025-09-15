import { IsIn, IsOptional } from 'class-validator';

export class GetMyInvitesDto {
  @IsOptional()
  @IsIn(['PENDING', 'ACCEPTED', 'DECLINED', 'CANCELED'])
  status?: 'PENDING' | 'ACCEPTED' | 'DECLINED' | 'CANCELED';
}
