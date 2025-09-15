import { Controller, Get, Post, Body, UseGuards, HttpCode } from '@nestjs/common';
import { InventoryService } from './inventory.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';
import { UserDocument } from '../auth/schemas/user.schema';
import { EquipItemDto } from './dto/equip-item.dto';
import { UnequipItemDto } from './dto/unequip-item.dto';


@UseGuards(JwtAuthGuard)
@Controller('inventory')
export class InventoryController {
  constructor(private readonly inventoryService: InventoryService) {}

  @Get('me')
  getMyInventory(@GetUser() user: UserDocument) {
    // Trả danh sách item đã mua (đã populate thông tin item)
    return this.inventoryService.getUserInventory(user._id.toString());
  }

  @Post('equip')
  equipItem(@GetUser() user: UserDocument, @Body() equipItemDto: EquipItemDto) {
    // Trang bị theo inventoryId
    return this.inventoryService.equipItem(user, equipItemDto.inventoryId);
  }

  @Post('unequip')
  unequipItem(@GetUser() user: UserDocument, @Body() dto: UnequipItemDto) {
    // Bỏ trang bị theo loại vật phẩm (AVATAR_FRAME, PROFILE_BACKGROUND, ...)
    return this.inventoryService.unequipItem(user, dto.type);
  }
}
