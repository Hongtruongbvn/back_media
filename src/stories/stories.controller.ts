import { Controller, Post, Get, Body, UseGuards } from '@nestjs/common';
import { StoriesService } from './stories.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';
import { UserDocument } from '../auth/schemas/user.schema';

@UseGuards(JwtAuthGuard)
@Controller('stories')
export class StoriesController {
    constructor(private storiesService: StoriesService) {}

    @Post()
    createStory(@GetUser() user: UserDocument, @Body() body: { mediaUrl: string; mediaType: 'IMAGE' | 'VIDEO' }) {
        return this.storiesService.createStory(user, body.mediaUrl, body.mediaType);
    }

    @Get()
    getActiveStories(@GetUser() user: UserDocument) {
        return this.storiesService.findActiveStories(user);
    }
}