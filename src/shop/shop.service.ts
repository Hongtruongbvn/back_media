import {
  Injectable,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import {
  ShopItem,
  ShopItemDocument,
  ItemType,
} from './schemas/shop-item.schema';
import { UserDocument } from '../auth/schemas/user.schema';
import { InventoryService } from '../inventory/inventory.service';
import { CreateShopItemDto } from './dto/create-shop-item.dto';
import { UpdateShopItemDto } from './dto/update-shop-item.dto';

@Injectable()
export class ShopService {
  constructor(
    @InjectModel(ShopItem.name) private shopItemModel: Model<ShopItemDocument>,
    private inventoryService: InventoryService,
  ) {}

  async listItems(types?: ItemType[]): Promise<ShopItem[]> {
    const filter = types?.length ? { type: { $in: types } } : {};
    return this.shopItemModel
      .find(filter)
      .sort({ createdAt: -1 })
      .lean()
      .exec();
  }

  async purchaseItem(
    user: UserDocument,
    itemId: string,
  ): Promise<{ message: string }> {
    const item = await this.shopItemModel.findById(itemId);
    if (!item) {
      throw new NotFoundException('Vật phẩm không tồn tại.');
    }

    const alreadyOwned = await this.inventoryService.hasItem(
      user._id.toString(),
      item._id.toString(),
    );
    if (alreadyOwned) {
      throw new BadRequestException('Bạn đã sở hữu vật phẩm này.');
    }

    if (user.coins < item.price) {
      throw new BadRequestException('Bạn không đủ coins để mua vật phẩm này.');
    }

    user.coins -= item.price;
    await user.save();

    await this.inventoryService.addItemToInventory(
      user._id.toString(),
      item._id.toString(),
    );

    return { message: `Mua thành công vật phẩm "${item.name}"!` };
  }

  async createItem(dto: CreateShopItemDto): Promise<ShopItem> {
    const newItem = new this.shopItemModel(dto);
    return newItem.save();
  }

  async updateItem(id: string, dto: UpdateShopItemDto): Promise<ShopItem> {
    const updated = await this.shopItemModel.findByIdAndUpdate(id, dto, {
      new: true,
    });
    if (!updated) throw new NotFoundException('Không tìm thấy vật phẩm.');
    return updated;
  }

  async deleteItem(id: string): Promise<{ message: string }> {
    const deleted = await this.shopItemModel.findByIdAndDelete(id);
    if (!deleted) throw new NotFoundException('Không tìm thấy vật phẩm.');
    return { message: 'Đã xóa vật phẩm thành công.' };
  }
  async getAllItems(): Promise<ShopItem[]> {
    return this.shopItemModel.find().sort({ createdAt: -1 }).lean().exec();
  }
}
