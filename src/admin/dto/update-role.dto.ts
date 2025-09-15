import { IsEnum, IsNotEmpty } from 'class-validator';
import { GlobalRole } from '../../auth/schemas/user.schema';

export class UpdateRoleDto {
  @IsNotEmpty()
  @IsEnum(GlobalRole)
  role: GlobalRole;
}