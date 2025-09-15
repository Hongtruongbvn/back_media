import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { CoinPackagesService } from './coin-packages.service';
import { CoinPackagesController } from './coin-packages.controller';
import { CoinPackage, CoinPackageSchema } from '../payments/schemas/coin-package.schema';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: CoinPackage.name, schema: CoinPackageSchema }]),
    AuthModule,
  ],
  controllers: [CoinPackagesController],
  providers: [CoinPackagesService],
})
export class CoinPackagesModule {}