import { Controller, Post, Delete, Get, Param, Req, UseGuards } from '@nestjs/common';
import { BlockService } from './block.service';
import { AuthGuard } from '@nestjs/passport';

@UseGuards(AuthGuard('jwt'))
@Controller('users')
export class BlockController {
  constructor(private readonly blockService: BlockService) {}

  // POST /users/:id/block
  @Post(':id/block')
  async block(@Param('id') targetId: string, @Req() req: any) {
    const meId = String(req.user?._id || req.user?.id);
    await this.blockService.block(meId, targetId);
    return await this.blockService.getStatus(meId, targetId);
  }

  // DELETE /users/:id/block
  @Delete(':id/block')
  async unblock(@Param('id') targetId: string, @Req() req: any) {
    const meId = String(req.user?._id || req.user?.id);
    await this.blockService.unblock(meId, targetId);
    return await this.blockService.getStatus(meId, targetId);
  }

  // GET /users/:id/block-status
  @Get(':id/block-status')
  async status(@Param('id') targetId: string, @Req() req: any) {
    const meId = String(req.user?._id || req.user?.id);
    return await this.blockService.getStatus(meId, targetId);
  }
}
