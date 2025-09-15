// apps/api/src/posts/posts.module.ts

import { Module } from '@nestjs/common';
import { PostsService } from './posts.service';
import { PostsController } from './posts.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { Post, PostSchema } from './schemas/post.schema';
import { Comment, CommentSchema } from './schemas/comment.schema';
import { AuthModule } from '../auth/auth.module';
import { NotificationsModule } from '../notifications/notifications.module';
import { GroupsModule } from '../groups/groups.module';
import { ModerationModule } from '../moderation/moderation.module'; // Thêm dòng này
import { MediaProcessingModule } from '../media-processing/media-processing.module';
import { UsersModule } from 'src/users/users.module';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Post.name, schema: PostSchema },
      { name: Comment.name, schema: CommentSchema },
    ]),
    UsersModule,
    AuthModule,
    NotificationsModule,
    GroupsModule,
    ModerationModule, // Và thêm vào đây
    MediaProcessingModule,
  ],
  controllers: [PostsController],
  providers: [PostsService],
})
export class PostsModule {}
