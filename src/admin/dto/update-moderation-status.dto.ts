import { IsEnum, IsNotEmpty } from 'class-validator';
// Sử dụng lại enum ModerationStatus đã có trong PostSchema
import { ModerationStatus } from '../../posts/schemas/post.schema';

export class UpdateModerationStatusDto {
  @IsNotEmpty()
  @IsEnum(ModerationStatus, { message: 'Trạng thái không hợp lệ.' })
  status: ModerationStatus.APPROVED | ModerationStatus.REJECTED;
}
