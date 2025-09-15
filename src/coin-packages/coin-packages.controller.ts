import {
  Body,
  Controller,
  Get,
  NotFoundException,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { CoinPackagesService } from './coin-packages.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CoinPackage } from 'src/payments/schemas/coin-package.schema';
import { CreateCoinPackageDto } from './dto/create-coin-package.dto';

@Controller('coin-packages')
export class CoinPackagesController {
  constructor(private readonly coinPackagesService: CoinPackagesService) {}

  // ✅ Public GET (không cần token)
  @Get()
  findAll() {
    return this.coinPackagesService.findAll();
  }

  // ✅ Tạo package (có thể thêm guard nếu chỉ admin được tạo)
  @Post()
  async create(@Body() dto: CreateCoinPackageDto): Promise<CoinPackage> {
    return this.coinPackagesService.createCoinPackage(dto);
  }

  @UseGuards(JwtAuthGuard)
  @Get(':packageId')
  async getById(@Param('packageId') packageId: string): Promise<CoinPackage> {
    const coinPack = await this.coinPackagesService.findOne(packageId);
    if (!coinPack) {
      throw new NotFoundException('Không tìm thấy gói coin');
    }
    return coinPack;
  }
}
