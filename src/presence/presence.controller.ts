import { Controller, Patch, Body, UseGuards } from '@nestjs/common';
import { PresenceService } from './presence.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';
import { UserDocument, PresenceStatus } from '../auth/schemas/user.schema';

@UseGuards(JwtAuthGuard)
@Controller('presence')
export class PresenceController {
    constructor(private presenceService: PresenceService) {}

    @Patch('status')
    setPresenceStatus(@GetUser() user: UserDocument, @Body('status') status: PresenceStatus) {
        return this.presenceService.setPresenceStatus(user._id.toString(), status);
    }
}