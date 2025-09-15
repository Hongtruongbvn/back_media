import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { LevelReward, LevelRewardDocument } from './schemas/level-reward.schema';
import { InventoryService } from '../inventory/inventory.service';
import { UserDocument } from '../auth/schemas/user.schema';

@Injectable()
export class RewardsService {
  constructor(
    @InjectModel(LevelReward.name) private rewardModel: Model<LevelRewardDocument>,
    private inventoryService: InventoryService,
  ) {}

  async grantLevelUpReward(user: UserDocument, newLevel: number) {
    const reward = await this.rewardModel.findOne({ level: newLevel });

    if (reward) {
      await this.inventoryService.addItemToInventory(user._id, reward.rewardItem as any);
      console.log(`User ${user.username} received reward for level ${newLevel}`);
      // (Tùy chọn) Gửi thông báo cho người dùng
    }
  }
}