import {
  Controller,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  UploadedFile,
  UseInterceptors,
  BadRequestException,
  Get,
  Query,
} from '@nestjs/common';
import { ShopService } from './shop.service';
import { CreateShopItemDto } from './dto/create-shop-item.dto';
import { UpdateShopItemDto } from './dto/update-shop-item.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { GlobalRole } from '../auth/schemas/user.schema';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { v4 as uuidv4 } from 'uuid';
import { extname, join } from 'path';
import * as fs from 'fs';
import { ItemType } from './schemas/shop-item.schema';
import { ApiBearerAuth, ApiConsumes, ApiTags } from '@nestjs/swagger';

@ApiTags('Admin Shop')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(GlobalRole.ADMIN)
@Controller('admin/shop')
export class AdminShopController {
  constructor(private readonly shopService: ShopService) {}

  @Get('items')
  async getAllItems(@Query('types') types?: string) {
    const itemTypes = types ? (types.split(',') as ItemType[]) : undefined;
    return this.shopService.listItems(itemTypes);
  }

  @Post('items')
  @UseInterceptors(
    FileInterceptor('file', {
      storage: diskStorage({
        destination: (req, file, cb) => {
          const dir = join(process.cwd(), 'uploads', 'shop-items');
          fs.mkdirSync(dir, { recursive: true });
          cb(null, dir);
        },
        filename: (req, file, cb) => {
          const ext = extname(file.originalname).toLowerCase();
          cb(null, `${uuidv4()}${ext}`);
        },
      }),
      limits: {
        fileSize: 5 * 1024 * 1024, // 5MB
      },
      fileFilter: (req, file, cb) => {
        if (!file.mimetype.startsWith('image/')) {
          return cb(new BadRequestException('Chỉ chấp nhận file ảnh'), false);
        }
        cb(null, true);
      },
    }),
  )
  @ApiConsumes('multipart/form-data')
  async createItem(
    @Body() dto: CreateShopItemDto,
    @UploadedFile() file?: Express.Multer.File,
  ) {
    if (!file && !dto.assetUrl) {
      throw new BadRequestException(
        'Vui lòng tải lên ảnh hoặc cung cấp URL ảnh',
      );
    }

    if (file) {
      dto.assetUrl = `/uploads/shop-items/${file.filename}`;
    }
    return this.shopService.createItem(dto);
  }

  @Patch('items/:id')
  async updateItem(
    @Param('id') id: string,
    @Body() updateShopItemDto: UpdateShopItemDto,
  ) {
    return this.shopService.updateItem(id, updateShopItemDto);
  }

  @Delete('items/:id')
  async deleteItem(@Param('id') id: string) {
    return this.shopService.deleteItem(id);
  }
}
