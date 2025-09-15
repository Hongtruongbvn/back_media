import { Controller, Get, Query, Post, Body, UseGuards, Delete } from '@nestjs/common';
import { GameActivityService } from './game-activity.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';
import { UserDocument } from '../auth/schemas/user.schema';
import { IgdbGameDto } from './dto/igdb-game.dto';

@UseGuards(JwtAuthGuard)
@Controller('game-activity')
export class GameActivityController {
  constructor(private readonly gameActivityService: GameActivityService) {}

  @Get('search')
  searchGames(@Query('q') query: string): Promise<IgdbGameDto[]> {
    return this.gameActivityService.searchGames(query ?? '');
  }

  @Post('playing')
  setPlayingStatus(
    @GetUser() user: UserDocument,
    @Body('gameId') gameId: number,
  ) {
    return this.gameActivityService.setPlayingStatus(user._id.toString(), gameId);
  }

  @Delete('playing')
  clearPlaying(@GetUser() user: UserDocument) {
    return this.gameActivityService.clearPlayingStatus(user._id.toString());
  }

  @Post('invite')
  inviteFriend(
    @GetUser() user: UserDocument,
    @Body('friendId') friendId: string,
  ) {
    return this.gameActivityService.inviteFriendToPlay(user, friendId);
  }

  // NEW
  @Get('friends-playing')
  getFriendsPlaying(@GetUser() user: UserDocument) {
    return this.gameActivityService.getFriendsPlaying(user._id.toString());
  }
}
