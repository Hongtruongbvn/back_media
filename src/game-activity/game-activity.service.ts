import {
  Injectable,
  BadRequestException,
  OnModuleInit,
  Logger,
} from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from '../auth/schemas/user.schema';
import { NotificationsService } from '../notifications/notifications.service';
import { NotificationType } from '../notifications/schemas/notification.schema';
import { PresenceService } from '../presence/presence.service';
import { IgdbGameDto } from './dto/igdb-game.dto';

export type FriendPlayingDto = {
  userId: string;
  username: string;
  avatarUrl: string;
  gameName: string;
  boxArtUrl: string;
  updatedAt: Date;
};

@Injectable()
export class GameActivityService implements OnModuleInit {
  private accessToken = '';
  private readonly igdbApiUrl = 'https://api.igdb.com/v4';
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly logger = new Logger(GameActivityService.name);

  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private notificationsService: NotificationsService,
    private presenceService: PresenceService,
  ) {
    this.clientId = this.configService.get<string>('IGDB_CLIENT_ID') ?? '';
    this.clientSecret = this.configService.get<string>('IGDB_CLIENT_SECRET') ?? '';
  }

  async onModuleInit() {
    await this.authenticate();
  }

  private async authenticate() {
    if (!this.clientId || !this.clientSecret) {
      this.logger.error('IGDB Client ID/Secret chưa cấu hình.');
      return;
    }
    const authUrl = `https://id.twitch.tv/oauth2/token?client_id=${this.clientId}&client_secret=${this.clientSecret}&grant_type=client_credentials`;
    try {
      const response = await firstValueFrom(this.httpService.post(authUrl));
      this.accessToken = response.data.access_token;
      this.logger.log('Đăng nhập IGDB/Twitch thành công.');
    } catch (error: any) {
      this.logger.error('Không thể xác thực IGDB/Twitch', error?.response?.data);
      this.accessToken = '';
    }
  }

  private async igdbPost<T>(endpoint: string, body: string): Promise<T> {
    const doRequest = () =>
      this.httpService.post<T>(`${this.igdbApiUrl}${endpoint}`, body, {
        headers: {
          'Client-ID': this.clientId,
          Authorization: `Bearer ${this.accessToken}`,
          Accept: 'application/json',
        },
      });

    if (!this.accessToken) await this.authenticate();

    try {
      const { data } = await firstValueFrom(doRequest());
      return data;
    } catch (err: any) {
      if (err?.response?.status === 401) {
        await this.authenticate();
        const { data } = await firstValueFrom(doRequest());
        return data;
      }
      throw err;
    }
  }

  async searchGames(query: string): Promise<IgdbGameDto[]> {
    if (!query?.trim()) return [];
    const body = `search "${query}"; fields name, cover.image_id; limit 20;`;
    try {
      return await this.igdbPost<IgdbGameDto[]>('/games', body);
    } catch (error: any) {
      this.logger.error('Lỗi tìm game IGDB:', error?.response?.data ?? error?.message);
      return [];
    }
  }

  private async getGameDetails(gameId: number): Promise<IgdbGameDto> {
    const body = `fields name, cover.image_id; where id = ${gameId};`;
    const data = await this.igdbPost<IgdbGameDto[]>('/games', body);
    if (!data?.length) {
      throw new BadRequestException(`Không tìm thấy game với ID ${gameId}`);
    }
    return data[0];
  }

  async setPlayingStatus(userId: string, gameId: number): Promise<UserDocument> {
    const gameDetails = await this.getGameDetails(gameId);
    const gameStatus = {
      igdbId: String(gameDetails.id),
      name: gameDetails.name,
      boxArtUrl: gameDetails.cover
        ? `https://images.igdb.com/igdb/image/upload/t_cover_big/${gameDetails.cover.image_id}.jpg`
        : '',
    };

    const updatedUser = await this.userModel.findByIdAndUpdate(
      userId,
      { $set: { currentGame: gameStatus } },
      { new: true },
    );
    if (!updatedUser) throw new BadRequestException('User not found');
    return updatedUser;
  }

  async clearPlayingStatus(userId: string): Promise<UserDocument> {
    const updated = await this.userModel.findByIdAndUpdate(
      userId,
      { $unset: { currentGame: '' } },
      { new: true },
    );
    if (!updated) throw new BadRequestException('User not found');
    return updated;
  }

  async inviteFriendToPlay(
    inviter: UserDocument,
    friendId: string,
  ): Promise<{ message: string }> {
    const isFriend = inviter.friends?.some((id: any) => id.toString() === friendId);
    if (!isFriend) {
      throw new BadRequestException('Bạn chỉ có thể mời người trong danh sách bạn bè.');
    }

    if (!inviter.currentGame?.name) {
      throw new BadRequestException('Bạn cần chọn game đang chơi trước khi mời.');
    }

    const online = await this.presenceService.isUserOnline(friendId);
    if (!online) {
      return { message: 'Người bạn này hiện không online.' };
    }

    const friend = await this.userModel.findById(friendId);
    if (!friend) throw new BadRequestException('Không tìm thấy người dùng được mời.');

    await this.notificationsService.createNotification(
      friend,
      inviter,
      NotificationType.GAME_INVITE,
      null,
      {
        gameName: inviter.currentGame.name,
        boxArtUrl: inviter.currentGame.boxArtUrl,
      },
    );

    return {
      message: `Đã gửi lời mời chơi ${inviter.currentGame.name} đến ${friend.username}.`,
    };
  }

  // -------- NEW: Hoạt động gần đây của bạn bè ----------
  async getFriendsPlaying(userId: string): Promise<FriendPlayingDto[]> {
    // 1) Lấy list friendIds nếu có trong User
    const me = await this.userModel.findById(userId).select('friends').lean();
    let friendIds: string[] =
      (me?.friends ?? []).map((id: any) => id.toString());

    this.logger.debug(
      `[friends-playing] user=${userId} friendIds=${friendIds.length}`,
    );

    // 2) Nếu KHÔNG có friends trong user (tuỳ hệ thống của bạn),
    // fallback: show người khác đang chơi để dễ test (loại trừ chính bạn)
    const filter: any =
      friendIds.length > 0
        ? { _id: { $in: friendIds } }
        : { _id: { $ne: userId } };

    // 3) Lọc những ai có currentGame
    const friends = await this.userModel
      .find({
        ...filter,
        'currentGame.igdbId': { $exists: true, $ne: null },
      })
      .select('username avatar avatarUrl currentGame updatedAt')
      .sort({ updatedAt: -1 })
      .limit(20)
      .lean();

    return (friends || []).map((f: any) => ({
      userId: String(f._id),
      username: f.username,
      avatarUrl: f.avatarUrl || f.avatar?.url || '',
      gameName: f.currentGame?.name || '',
      boxArtUrl: f.currentGame?.boxArtUrl || '',
      updatedAt: f.updatedAt,
    }));
  }
}
