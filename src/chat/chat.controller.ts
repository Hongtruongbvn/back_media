import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  UseGuards,
  ValidationPipe,
  UseInterceptors,
  UploadedFile,
  Patch,
  Delete,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { extname, join } from 'path';
import * as fs from 'fs';

import { ChatService } from './chat.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';
import { UserDocument } from '../auth/schemas/user.schema';
import { CreateRoomDto } from './dto/create-room.dto';

function ensureDir(dir: string) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

@UseGuards(JwtAuthGuard)
@Controller('chat')
export class ChatController {
  constructor(private readonly chatService: ChatService) {}

  @Post('rooms')
  @UseInterceptors(
    FileInterceptor('avatar', {
      storage: diskStorage({
        destination: (_req, _file, cb) => {
          const dest = join(process.cwd(), 'uploads', 'groups');
          ensureDir(dest);
          cb(null, dest);
        },
        filename: (_req, file, cb) => {
          const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
          cb(null, unique + extname(file.originalname));
        },
      }),
      limits: { fileSize: 5 * 1024 * 1024 },
    }),
  )
  createRoom(
    @GetUser() user: UserDocument,
    @UploadedFile() avatar: Express.Multer.File | undefined,
    @Body(new ValidationPipe({ whitelist: true, transform: true }))
    createRoomDto: CreateRoomDto,
  ) {
    return this.chatService.createChatroom(
      user,
      Array.isArray(createRoomDto.memberIds)
        ? createRoomDto.memberIds
        : [createRoomDto.memberIds].filter(Boolean),
      createRoomDto.name,
      avatar,
    );
  }

  @Get('rooms')
  findRooms(@GetUser() user: UserDocument) {
    return this.chatService.findRoomsForUser(user);
  }

  @Get('rooms/:id/messages')
  findMessages(@GetUser() user: UserDocument, @Param('id') chatroomId: string) {
    return this.chatService.findMessagesInRoomForUser(user._id, chatroomId);
  }

  // ---------- Thêm thành viên ----------
  @Post('rooms/:id/members')
  async addMembers(
    @GetUser() user: UserDocument,
    @Param('id') chatroomId: string,
    @Body(new ValidationPipe({ whitelist: true, transform: true })) body: { memberIds: string[] },
  ) {
    return this.chatService.addMembersToGroup(user, chatroomId, body.memberIds || []);
  }

  // ---------- Kick thành viên ----------
  @Delete('rooms/:id/members/:userId')
  async removeMember(
    @GetUser() user: UserDocument,
    @Param('id') chatroomId: string,
    @Param('userId') targetUserId: string,
  ) {
    return this.chatService.removeMemberFromGroup(user, chatroomId, targetUserId);
  }

  // ---------- RỜI NHÓM (member tự rời) ----------
  @Delete('rooms/:id/members/me')
  async leaveMyself(
    @GetUser() user: UserDocument,
    @Param('id') chatroomId: string,
  ) {
    return this.chatService.leaveRoom(user, chatroomId);
  }

  // Fallback để FE cũ / fallback khác vẫn dùng được
  @Post('rooms/:id/leave')
  async leaveCompat(
    @GetUser() user: UserDocument,
    @Param('id') chatroomId: string,
  ) {
    return this.chatService.leaveRoom(user, chatroomId);
  }

  // ---------- Đổi avatar nhóm ----------
  @Patch('rooms/:id/avatar')
  @UseInterceptors(
    FileInterceptor('avatar', {
      storage: diskStorage({
        destination: (_req, _file, cb) => {
          const dest = join(process.cwd(), 'uploads', 'groups');
          ensureDir(dest);
          cb(null, dest);
        },
        filename: (_req, file, cb) => {
          const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
          cb(null, unique + extname(file.originalname));
        },
      }),
      limits: { fileSize: 5 * 1024 * 1024 },
    }),
  )
  async updateAvatar(
    @GetUser() user: UserDocument,
    @Param('id') chatroomId: string,
    @UploadedFile() avatar: Express.Multer.File | undefined,
  ) {
    return this.chatService.updateGroupAvatar(user, chatroomId, avatar);
  }

  // ---------- XÓA NHÓM (chỉ chủ nhóm) ----------
  @Delete('rooms/:id')
  async deleteRoom(
    @GetUser() user: UserDocument,
    @Param('id') chatroomId: string,
  ) {
    return this.chatService.deleteRoomAsOwner(user, chatroomId);
  }

  // Fallback (POST) cho FE cũ
  @Post('rooms/:id/delete')
  async deleteRoomCompat(
    @GetUser() user: UserDocument,
    @Param('id') chatroomId: string,
  ) {
    return this.chatService.deleteRoomAsOwner(user, chatroomId);
  }
}
