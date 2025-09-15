import {
  Controller,
  Get,
  Post,
  UseGuards,
  Body,
  HttpCode,
  Query,
} from '@nestjs/common';
import { ShopService } from './shop.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';
import { UserDocument } from '../auth/schemas/user.schema';
import { PurchaseItemDto } from './dto/purchase-item.dto';
import { ItemType } from './schemas/shop-item.schema';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';

@ApiTags('Shop')
@ApiBearerAuth()
@Controller('shop')
export class ShopController {
  constructor(private readonly shopService: ShopService) {}

  @Get('items')
  async listItems(@Query('types') types?: string) {
    const defaultTypes = [
      ItemType.AVATAR_FRAME,
      ItemType.PROFILE_BACKGROUND,
      ItemType.PROFILE_EFFECT,
      ItemType.AVATAR_DECORATION,
      ItemType.NAMEPLATE_THEME,
    ];

    const itemTypes = types ? (types.split(',') as ItemType[]) : defaultTypes;

    return this.shopService.listItems(itemTypes);
  }

  @UseGuards(JwtAuthGuard)
  @Post('purchase')
  @HttpCode(200)
  async purchaseItem(
    @GetUser() user: UserDocument,
    @Body() purchaseItemDto: PurchaseItemDto,
  ) {
    return this.shopService.purchaseItem(user, purchaseItemDto.itemId);
  }
}
