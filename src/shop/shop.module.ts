import { Module } from '@nestjs/common';
import { ShopController } from './shop.controller';
import { ShopService } from './shop.service';
import { MongooseModule } from '@nestjs/mongoose';
import { ShopItem, ShopItemSchema } from './schemas/shop-item.schema';
import { AuthModule } from '../auth/auth.module';
import { InventoryModule } from '../inventory/inventory.module'; // <-- Thêm InventoryModule
import { AdminShopController } from './admin-shop.controller';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: ShopItem.name, schema: ShopItemSchema }
    ]), 
    AuthModule,
    InventoryModule, // <-- Thêm vào đây
  ],
  controllers: [ShopController,AdminShopController],
  providers: [ShopService],
})
export class ShopModule {}
