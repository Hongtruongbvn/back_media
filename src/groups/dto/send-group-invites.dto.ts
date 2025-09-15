import { ArrayNotEmpty, IsArray, IsMongoId } from 'class-validator';

export class SendGroupInvitesDto {
  @IsArray()
  @ArrayNotEmpty()
  @IsMongoId({ each: true })
  inviteeIds!: string[];
}
