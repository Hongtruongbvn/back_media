import { Module } from '@nestjs/common';
import { MediaProcessingService } from './media-processing.service';
import { ModerationModule } from '../moderation/moderation.module';
import { MongooseModule } from '@nestjs/mongoose';
import { Post, PostSchema } from '../posts/schemas/post.schema';

@Module({
  imports: [
    ModerationModule,
    MongooseModule.forFeature([{ name: Post.name, schema: PostSchema }]),
  ],
  providers: [MediaProcessingService],
})
export class MediaProcessingModule {}