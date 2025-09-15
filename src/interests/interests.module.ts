import { Module } from '@nestjs/common';
import { InterestsService } from './interests.service';
import { InterestsController } from './interests.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { Interest, InterestSchema } from './schemas/interest.schema';
import { AuthModule } from '../auth/auth.module';
import { AdminInterestsController } from './admin-interests.controller'; // Import controller mới

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Interest.name, schema: InterestSchema }]),
    AuthModule,
  ],
  // Thêm AdminInterestsController vào danh sách controllers
  controllers: [InterestsController, AdminInterestsController],
  providers: [InterestsService],
})
export class InterestsModule {}
