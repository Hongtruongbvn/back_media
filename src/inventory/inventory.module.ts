// apps/api/src/inventory/inventory.module.ts

import { Module } from '@nestjs/common';
import { InventoryController } from './inventory.controller';
import { InventoryService } from './inventory.service';
import { MongooseModule } from '@nestjs/mongoose';
import { UserInventory, UserInventorySchema } from './schemas/user-inventory.schema';
import { User, UserSchema } from '../auth/schemas/user.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: UserInventory.name, schema: UserInventorySchema },
      { name: User.name, schema: UserSchema }, // Thêm UserModel vào đây
    ]),
  ],
  controllers: [InventoryController],
  providers: [InventoryService],
  exports: [InventoryService],
})
export class InventoryModule {}