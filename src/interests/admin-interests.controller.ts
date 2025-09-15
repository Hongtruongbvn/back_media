import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
} from '@nestjs/common';
import { InterestsService } from './interests.service';
import { CreateInterestDto } from './dto/create-interest.dto';
import { UpdateInterestDto } from './dto/update-interest.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { GlobalRole } from '../auth/schemas/user.schema';

@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(GlobalRole.ADMIN)
@Controller('admin/interests') // Đặt route dưới tiền tố /admin
export class AdminInterestsController {
  constructor(private readonly interestsService: InterestsService) {}

  @Post()
  create(@Body() createInterestDto: CreateInterestDto) {
    return this.interestsService.create(createInterestDto);
  }

  // Ghi chú: GET /interests đã có ở controller công khai,
  // nên ở đây không cần, Admin có thể dùng chung API đó để xem.

  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updateInterestDto: UpdateInterestDto,
  ) {
    return this.interestsService.update(id, updateInterestDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.interestsService.remove(id);
  }
  @Delete()
  async removeMany(@Body('ids') ids: string[]) {
    await Promise.all(ids.map((id) => this.interestsService.remove(id)));
    return { message: 'Đã xóa các sở thích đã chọn.' };
  }
}
