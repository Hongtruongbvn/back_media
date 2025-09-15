import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { User } from '../../auth/schemas/user.schema';

export type ReportDocument = Report & Document;

export enum ReportType {
    POST = 'POST',
    COMMENT = 'COMMENT',
    USER = 'USER',
}

@Schema({ timestamps: true })
export class Report {
  @Prop({ required: true, type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  reporter: User; // Người báo cáo

  @Prop({ required: true, enum: ReportType })
  type: ReportType;

  @Prop({ required: true })
  targetId: string; // ID của post, comment, hoặc user bị báo cáo

  @Prop({ required: true })
  reason: string;
}

export const ReportSchema = SchemaFactory.createForClass(Report);