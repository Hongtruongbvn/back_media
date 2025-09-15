import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Settings, SettingsDocument } from './schemas/settings.schema';
import { UpdateSettingsDto } from './dto/update-settings.dto';

@Injectable()
export class SettingsService {
  constructor(@InjectModel(Settings.name) private settingsModel: Model<SettingsDocument>) {}

  /**
   * Lấy cài đặt hiện tại của trang web.
   * Nếu chưa có, sẽ tự động tạo một bản ghi cài đặt mặc định.
   */
  async getSettings(): Promise<SettingsDocument> { // SỬA LỖI: Trả về SettingsDocument
    let settings = await this.settingsModel.findOne({ key: 'singleton_key' }).exec();
    if (!settings) {
      // new this.settingsModel() tạo ra một document mới và .save() lưu nó lại
      settings = await new this.settingsModel().save();
    }
    return settings;
  }

  /**
   * Cập nhật cài đặt trang web.
   */
  async updateSettings(updateSettingsDto: UpdateSettingsDto): Promise<SettingsDocument> { // SỬA LỖI: Trả về SettingsDocument
    // getSettings giờ đã trả về một document đầy đủ, nên có thể gọi .save()
    const settings = await this.getSettings();
    Object.assign(settings, updateSettingsDto);
    return settings.save();
  }
}