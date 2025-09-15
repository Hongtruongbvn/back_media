import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  UseInterceptors,
  UploadedFile,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { extname } from 'path';
import { UsersService } from './users.service';
import { UpdateUserDto } from './dto/update-user.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';
import { UserDocument } from '../auth/schemas/user.schema';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  // ===== AUTH-REQUIRED =====
  @UseGuards(JwtAuthGuard)
  @Get('me')
  getMe(@GetUser() user: UserDocument) {
    return this.usersService.getMe(user._id.toString());
  }

  // ===== PUBLIC / STATIC PATHS (đặt TRƯỚC đường dẫn động) =====
  @Get('by-id/:id')
  findPublicById(@Param('id') id: string) {
    return this.usersService.findPublicById(id);
  }

  @UseGuards(JwtAuthGuard)
  @Get('get/friends')
  getAllFriend(@GetUser() user: UserDocument) {
    return this.usersService.getAllFriend(user._id.toString());
  }

  @UseGuards(JwtAuthGuard)
  @Get('get/dental/:id')
  getDental(@Param('id') id: string) {
    return this.usersService.GetUserDental(id);
  }

  @UseGuards(JwtAuthGuard)
  @Get('warnings/get')
  getWarnings(@GetUser() user: UserDocument) {
    return this.usersService.getWarnings(user._id.toString());
  }

  @UseGuards(JwtAuthGuard)
  @Delete('warnings/delete/:warningId')
  deleteWarning(
    @GetUser() user: UserDocument,
    @Param('warningId') warningId: string,
  ) {
    return this.usersService.deleteWarning(user._id.toString(), warningId);
  }

  // ===== PUBLIC / DYNAMIC (nhận cả username hoặc ObjectId) =====
  @Get(':param')
  findByUsernameOrId(@Param('param') param: string) {
    return this.usersService.findByUsernameOrId(param);
  }

  // ===== PATCH / MUTATIONS =====
@Patch('me')
@UseGuards(JwtAuthGuard)
updateMyProfile(
  @GetUser() user: UserDocument,
  @Body() updateUserDto: UpdateUserDto,
) {
  // LOGIC MỚI: Kiểm tra xem DTO có chứa sở thích không
  if (updateUserDto.interests && Array.isArray(updateUserDto.interests)) {
    // Nếu có, gọi hàm updateUserInterests chuyên dụng
    return this.usersService.updateUserInterests(
      user._id.toString(),
      updateUserDto.interests,
    );
  }

  // Nếu không có sở thích, giữ nguyên logic cũ cho web và các cập nhật khác
  return this.usersService.updateProfile(user._id.toString(), updateUserDto);
}

  @UseGuards(JwtAuthGuard)
  @Patch('me/avatar')
  @UseInterceptors(
    FileInterceptor('avatar', {
      storage: diskStorage({
        destination: './uploads/avatars',
        filename: (_req, file, cb) => {
          const uniqueSuffix = Date.now() + extname(file.originalname);
          cb(null, `avatar-${uniqueSuffix}`);
        },
      }),
    }),
  )
  uploadAvatar(
    @GetUser() user: UserDocument,
    @UploadedFile() file: Express.Multer.File,
  ) {
    const avatarPath = `/uploads/avatars/${file.filename}`;
    return this.usersService.updateAvatar(user._id.toString(), avatarPath);
  }

  @UseGuards(JwtAuthGuard)
  @Patch('me/cover')
  @UseInterceptors(
    FileInterceptor('cover', {
      storage: diskStorage({
        destination: './uploads/covers',
        filename: (_req, file, cb) => {
          const uniqueSuffix = Date.now() + extname(file.originalname);
          cb(null, `cover-${uniqueSuffix}`);
        },
      }),
    }),
  )
  uploadCover(
    @GetUser() user: UserDocument,
    @UploadedFile() file: Express.Multer.File,
  ) {
    const coverPath = `/uploads/covers/${file.filename}`;
    return this.usersService.updateCover(user._id.toString(), coverPath);
  }

  @UseGuards(JwtAuthGuard)
  @Post(':id/follow')
  followUser(
    @GetUser() currentUser: UserDocument,
    @Param('id') userIdToFollow: string,
  ) {
    return this.usersService.followUser(
      currentUser._id.toString(),
      userIdToFollow,
    );
  }

  @UseGuards(JwtAuthGuard)
  @Delete(':id/follow')
  unfollowUser(
    @GetUser() currentUser: UserDocument,
    @Param('id') userIdToUnfollow: string,
  ) {
    return this.usersService.unfollowUser(
      currentUser._id.toString(),
      userIdToUnfollow,
    );
  }

  @UseGuards(JwtAuthGuard)
  @Patch('me/interests')
  updateInterests(
    @GetUser() user: UserDocument,
    @Body('interestIds') interestIds: string[],
  ) {
    return this.usersService.updateUserInterests(
      user._id.toString(),
      interestIds,
    );
  }
}
