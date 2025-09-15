// apps/api/src/rewards/rewards.module.ts
import { Module } from '@nestjs/common';
import { RewardsService } from './rewards.service';
import { InventoryModule } from '../inventory/inventory.module';
import { MongooseModule } from '@nestjs/mongoose';
import { LevelReward, LevelRewardSchema } from './schemas/level-reward.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: LevelReward.name, schema: LevelRewardSchema }
    ]), 
    InventoryModule
  ],
  providers: [RewardsService],
  exports: [RewardsService], 
})
export class RewardsModule {}