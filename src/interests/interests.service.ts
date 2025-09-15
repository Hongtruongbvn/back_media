import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Interest, InterestDocument } from './schemas/interest.schema';
import { CreateInterestDto } from './dto/create-interest.dto';
import { UpdateInterestDto } from './dto/update-interest.dto';

@Injectable()
export class InterestsService {
  constructor(
    @InjectModel(Interest.name) private interestModel: Model<InterestDocument>,
  ) {}

  async findAll(): Promise<Interest[]> {
    return this.interestModel.find().exec();
  }
  // --- HÀM MỚI CHO ADMIN ---
  async create(createInterestDto: CreateInterestDto): Promise<Interest> {
    const newInterest = new this.interestModel(createInterestDto);
    return newInterest.save();
  }

  async update(
    id: string,
    updateInterestDto: UpdateInterestDto,
  ): Promise<Interest> {
    const updatedInterest = await this.interestModel.findByIdAndUpdate(
      id,
      updateInterestDto,
      { new: true },
    );
    if (!updatedInterest) {
      throw new NotFoundException(`Không tìm thấy sở thích với ID: ${id}`);
    }
    return updatedInterest;
  }

  async remove(id: string): Promise<{ message: string }> {
    const result = await this.interestModel.findByIdAndDelete(id);
    if (!result) {
      throw new NotFoundException(`Không tìm thấy sở thích với ID: ${id}`);
    }
    // (Nâng cao) Cần có logic để xóa sở thích này khỏi tất cả các user đang có nó.
    // Tạm thời để đơn giản, chúng ta chỉ xóa sở thích.
    return { message: 'Đã xóa sở thích thành công.' };
  }
  async findOne(id: string): Promise<Interest> {
    const interest = await this.interestModel.findById(id);
    if (!interest) {
      throw new NotFoundException(`Không tìm thấy sở thích với ID: ${id}`);
    }
    return interest;
  }
}
