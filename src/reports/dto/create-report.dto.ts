import { IsEnum, IsNotEmpty, IsString } from 'class-validator';
import { ReportType } from '../schemas/report.schema';

export class CreateReportDto {
  @IsNotEmpty()
  @IsEnum(ReportType)
  readonly type: ReportType;

  @IsNotEmpty()
  @IsString()
  readonly targetId: string;

  @IsNotEmpty()
  @IsString()
  readonly reason: string;
}