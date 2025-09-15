import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import {
  CoinPackage,
  CoinPackageDocument,
} from '../payments/schemas/coin-package.schema';
import { CreateCoinPackageDto } from './dto/create-coin-package.dto';

@Injectable()
export class CoinPackagesService {
  constructor(
    @InjectModel(CoinPackage.name)
    private coinPackageModel: Model<CoinPackageDocument>,
  ) {}

  async findAll(): Promise<CoinPackage[]> {
    return this.coinPackageModel.find().exec();
  }

  async createCoinPackage(dto: CreateCoinPackageDto): Promise<CoinPackage> {
    const newPackage = new this.coinPackageModel(dto);
    return await newPackage.save();
  }

  async findOne(packageId: string): Promise<CoinPackage | null> {
    return this.coinPackageModel.findOne({ packageId });
  }
}
