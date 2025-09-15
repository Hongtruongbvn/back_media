import {
  IsString,
  IsOptional,
  IsArray,
  IsIn,
  IsNotEmpty,
} from 'class-validator';

/**
 * DTO để cập nhật thông tin nhóm.
 * Tất cả các trường đều là tùy chọn (optional), cho phép client
 * chỉ gửi những thông tin họ muốn thay đổi.
 *
 * LƯU Ý: Phiên bản này được định nghĩa thủ công để loại bỏ
 * sự phụ thuộc vào gói `@nestjs/mapped-types`,
 * qua đó khắc phục lỗi "Cannot find module".
 */
export class UpdateGroupDto {
  @IsOptional()
  @IsNotEmpty({ message: 'Tên nhóm không được để trống.' })
  @IsString()
  name?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  interestIds?: string[];

  @IsOptional()
  @IsString()
  @IsIn(['public', 'private'])
  privacy?: 'public' | 'private';
}
