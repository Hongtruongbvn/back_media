import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { Block, BlockDocument } from './schemas/block.schema';

@Injectable()
export class BlockService {
  constructor(@InjectModel(Block.name) private blockModel: Model<BlockDocument>) {}

  private toId(id: string | Types.ObjectId) {
    return typeof id === 'string' ? new Types.ObjectId(id) : id;
  }

  async block(blockerId: string, targetId: string) {
    if (String(blockerId) === String(targetId)) {
      throw new BadRequestException('Cannot block yourself');
    }
    const blocker = this.toId(blockerId);
    const blocked = this.toId(targetId);
    await this.blockModel.updateOne({ blocker, blocked }, {}, { upsert: true, setDefaultsOnInsert: true });
    return { ok: true };
  }

  async unblock(blockerId: string, targetId: string) {
    const blocker = this.toId(blockerId);
    const blocked = this.toId(targetId);
    await this.blockModel.deleteOne({ blocker, blocked });
    return { ok: true };
  }

  async getStatus(meId: string, targetId: string) {
    const [byMe, meBy] = await Promise.all([
      this.blockModel.exists({ blocker: this.toId(meId),   blocked: this.toId(targetId) }),
      this.blockModel.exists({ blocker: this.toId(targetId), blocked: this.toId(meId) }),
    ]);
    return { blockedByMe: !!byMe, blockedMe: !!meBy };
  }

  async isBlockedEither(a: string, b: string) {
    const found = await this.blockModel.exists({
      $or: [
        { blocker: this.toId(a), blocked: this.toId(b) },
        { blocker: this.toId(b), blocked: this.toId(a) },
      ],
    });
    return !!found;
  }
}
