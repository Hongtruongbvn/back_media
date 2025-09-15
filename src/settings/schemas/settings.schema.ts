import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type SettingsDocument = Settings & Document;

@Schema({ timestamps: true })
export class Settings {
  @Prop({ required: true, unique: true, default: 'singleton_key' })
  key: string; // Dùng để đảm bảo chỉ có một document cài đặt duy nhất

  @Prop({ required: true, default: 'GrandProject' })
  siteName: string;

  @Prop({ default: 'Một mạng xã hội tuyệt vời cho cộng đồng.' })
  siteDescription: string;

  @Prop()
  logoUrl?: string;

  @Prop()
  faviconUrl?: string;
}

export const SettingsSchema = SchemaFactory.createForClass(Settings);
