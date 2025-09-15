import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Report, ReportDocument } from './schemas/report.schema';
import { UserDocument } from '../auth/schemas/user.schema';
import { CreateReportDto } from './dto/create-report.dto';

@Injectable()
export class ReportsService {
  constructor(
    @InjectModel(Report.name) private reportModel: Model<ReportDocument>,
  ) {}

  async createReport(
    reporter: UserDocument,
    createReportDto: CreateReportDto,
  ): Promise<{ message: string }> {
    const newReport = new this.reportModel({
      type: createReportDto.type,
      targetId: createReportDto.targetId,
      reason: createReportDto.reason,
      reporter: reporter._id,
    });
    await newReport.save();
    return { message: 'Cảm ơn bạn đã gửi báo cáo. Chúng tôi sẽ xem xét nó.' };
  }

  // Hàm cho Admin xem báo cáo
  async findAllReports(): Promise<Report[]> {
    return this.reportModel
      .find()
      .populate('reporter', 'username avatar')
      .sort({ createdAt: -1 })
      .exec();
  }
  async findReportsByTargetId(targetId: string): Promise<Report[]> {
    return this.reportModel
      .find({ targetId })
      .populate('reporter', 'username avatar')
      .sort({ createdAt: -1 })
      .exec();
  }
}
