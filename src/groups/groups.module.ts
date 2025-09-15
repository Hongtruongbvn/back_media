import { Module } from '@nestjs/common';
import { GroupsService } from './groups.service';
import { GroupsController, MyGroupInvitesController } from './groups.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { Group, GroupSchema } from './schemas/group.schema';
import { GroupMember, GroupMemberSchema } from './schemas/group-member.schema';
import { AuthModule } from '../auth/auth.module';
import { RewardsModule } from '../rewards/rewards.module';
import { UsersModule } from '../users/users.module';
// --- BỔ SUNG CÁC IMPORT CÒN THIẾU ---
import { User, UserSchema } from '../auth/schemas/user.schema';
import { Post, PostSchema } from '../posts/schemas/post.schema';
import { Comment, CommentSchema } from '../posts/schemas/comment.schema';
import { JoinRequest, JoinRequestSchema } from './schemas/join-request.schema'; 
import { GroupOwnerGuard } from './guards/group-owner.guard';
import { GroupMemberGuard } from './guards/group-member.guard';
import { GroupInvite, GroupInviteSchema } from './schemas/group-invite.schema';
import { NotificationsModule } from '../notifications/notifications.module';

@Module({
  imports: [
    MongooseModule.forFeature([
      
      { name: Group.name, schema: GroupSchema },
      { name: GroupMember.name, schema: GroupMemberSchema },
      { name: User.name, schema: UserSchema },
      { name: Post.name, schema: PostSchema },
      { name: Comment.name, schema: CommentSchema },
      { name: JoinRequest.name, schema: JoinRequestSchema },
       { name: GroupInvite.name, schema: GroupInviteSchema },
       { name: GroupInvite.name, schema: GroupInviteSchema },
    ]),
    AuthModule,
    RewardsModule,
    UsersModule, // <-- Thêm UsersModule để sử dụng UserService
    NotificationsModule,
  ],
  controllers: [GroupsController, MyGroupInvitesController,],
  providers: [GroupsService, GroupOwnerGuard, GroupMemberGuard],
  exports: [GroupsService], // Export để PostsModule có thể dùng
})
export class GroupsModule {}