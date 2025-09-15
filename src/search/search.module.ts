// File: apps/api/src/search/search.module.ts (Mới)
import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { SearchService } from './search.service';
import { SearchController } from './search.controller';
import { User, UserSchema } from '../auth/schemas/user.schema';
import { Post, PostSchema } from '../posts/schemas/post.schema';
import { Group, GroupSchema } from '../groups/schemas/group.schema';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: Post.name, schema: PostSchema },
      { name: Group.name, schema: GroupSchema },
    ]),
    AuthModule,
  ],
  controllers: [SearchController],
  providers: [SearchService],
})
export class SearchModule {}