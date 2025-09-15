import { Controller, Post, Body, UseGuards, Get, Param } from '@nestjs/common';
import { ReportsService } from './reports.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';
import { UserDocument } from '../auth/schemas/user.schema';
import { CreateReportDto } from './dto/create-report.dto';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { GlobalRole } from '../auth/schemas/user.schema';

@UseGuards(JwtAuthGuard)
@Controller('reports')
export class ReportsController {
  constructor(private readonly reportsService: ReportsService) {}

  @Post()
  createReport(
    @GetUser() user: UserDocument,
    @Body() createReportDto: CreateReportDto,
  ) {
    return this.reportsService.createReport(user, createReportDto);
  }

  // Endpoint cho Admin xem tất cả báo cáo
  // Sau này chúng ta sẽ thay JwtAuthGuard bằng một AdminGuard riêng
  // Bảo vệ endpoint này, chỉ ADMIN mới có thể truy cập
  @Get('all')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(GlobalRole.ADMIN)
  findAllReports() {
    return this.reportsService.findAllReports();
  }
  @Get('target/:targetId')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(GlobalRole.ADMIN)
  getReportsByTarget(@Param('targetId') targetId: string) {
    return this.reportsService.findReportsByTargetId(targetId);
  }
}
