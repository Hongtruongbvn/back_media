import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import {
  Post,
  PostDocument,
  ModerationStatus,
  PostVisibility,
} from './schemas/post.schema';
import { Comment, CommentDocument } from './schemas/comment.schema';
import { CreatePostDto } from './dto/create-post.dto';
import { UserDocument } from '../auth/schemas/user.schema';
import { CreateCommentDto } from './dto/create-comment.dto';
import { NotificationsService } from '../notifications/notifications.service';
import { NotificationType } from '../notifications/schemas/notification.schema';
import { GroupsService } from '../groups/groups.service';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { ModerationService } from '../moderation/moderation.service';
import { ReactToPostDto } from './dto/react-to-post.dto';
import { RepostDto } from './dto/repost.dto';
import { UpdatePostDto } from './dto/update-post.dto';
import { UpdateCommentDto } from './dto/update-comment.dto';
// Thay dòng 28:
import { UsersService } from '../users/users.service';
import { GroupDocument } from '../groups/schemas/group.schema';
@Injectable()
export class PostsService {
  constructor(
    @InjectModel(Post.name) private postModel: Model<PostDocument>,
    @InjectModel(Comment.name) private commentModel: Model<CommentDocument>,
    private notificationsService: NotificationsService,
    private groupsService: GroupsService,
    private moderationService: ModerationService,
    private userService: UsersService,

    private eventEmitter: EventEmitter2,
  ) {}
  async replyComment(
    parentCommentId: string,
    user: UserDocument,
    createCommentDto: CreateCommentDto,
  ): Promise<Comment> {
    const parentComment = await this.commentModel.findById(parentCommentId);
    if (!parentComment) {
      throw new NotFoundException('Không tìm thấy bình luận cha');
    }

    const textModeration = await this.moderationService.checkText(
      createCommentDto.content,
    );
    if (textModeration.status === ModerationStatus.REJECTED) {
      throw new BadRequestException(
        `Bình luận của bạn không phù hợp: ${textModeration.reason}`,
      );
    }

    const newReply = new this.commentModel({
      ...createCommentDto,
      author: user._id,
      post: parentComment.post,
      parentComment: parentCommentId,
      moderationStatus: ModerationStatus.APPROVED,
    });

    // Tăng replyCount của comment cha
    parentComment.replyCount = (parentComment.replyCount || 0) + 1;
    await parentComment.save();

    // Tăng commentCount của post
    await this.postModel.findByIdAndUpdate(parentComment.post, {
      $inc: { commentCount: 1 },
    });

    await this.userService.receiveXP(3, 'reply', user.id);

    const savedReply = await newReply.save();
    await savedReply.populate({ path: 'author', select: 'username avatar' });

    // Gửi notification
    if (parentComment.author.toString() !== user._id.toString()) {
      await this.notificationsService.createNotification(
        parentComment.author as UserDocument,
        user,
        NotificationType.NEW_REPLY,
        `/posts/${parentComment.post}`,
      );
    }

    return savedReply;
  }

  async deleteComment(id: string) {
    const comment = await this.commentModel.findById(id);
    if (!comment) {
      throw new NotFoundException('Không tìm thấy bình luận');
    }

    // Nếu là reply, giảm replyCount của comment cha
    if (comment.parentComment) {
      await this.commentModel.findByIdAndUpdate(comment.parentComment, {
        $inc: { replyCount: -1 },
      });
    }

    // Giảm commentCount trong post
    await this.postModel.findByIdAndUpdate(comment.post, {
      $inc: { commentCount: -1 },
    });

    // Xóa tất cả replies
    if (comment.replyCount > 0) {
      await this.commentModel.deleteMany({ parentComment: id });
      await this.postModel.findByIdAndUpdate(comment.post, {
        $inc: { commentCount: -comment.replyCount },
      });
    }

    return await this.commentModel.findByIdAndDelete(id);
  }

  async getCommentReplies(commentId: string): Promise<Comment[]> {
    return this.commentModel
      .find({
        parentComment: commentId,
        moderationStatus: ModerationStatus.APPROVED,
      })
      .populate('author', 'username avatar')
      .sort({ createdAt: 'asc' })
      .exec();
  }
  async createPost(
    user: UserDocument,
    createPostDto: CreatePostDto,
  ): Promise<Post> {
    // --- XỬ LÝ REPOST ---
    if (createPostDto.repostOf) {
      const originalPost = await this.postModel.findById(
        createPostDto.repostOf,
      );
      if (!originalPost) {
        throw new NotFoundException('Bài viết gốc không tồn tại.');
      }

      const repost = new this.postModel({
        content: createPostDto.content || '',
        author: user._id,
        repostOf: originalPost._id,
        visibility: createPostDto.visibility || 'FRIENDS_ONLY',
        moderationStatus: ModerationStatus.APPROVED,
      });

      originalPost.repostCount += 1;
      await originalPost.save();
      await this.userService.receiveXP(10, 'repost', user.id);
      const savedRepost = await repost.save();

      return savedRepost.populate([
        { path: 'author', select: 'username avatar' },
        {
          path: 'repostOf',
          populate: { path: 'author', select: 'username avatar' },
        },
      ]);
    }

    // --- XỬ LÝ BÀI VIẾT THƯỜNG ---
    const textModeration = await this.moderationService.checkText(
      createPostDto.content,
    );
    if (textModeration.status === ModerationStatus.REJECTED) {
      throw new BadRequestException(
        `Nội dung của bạn không phù hợp: ${textModeration.reason}`,
      );
    }

    const isVideoPost =
      createPostDto.mediaUrls && createPostDto.mediaUrls[0]?.includes('.mp4');

    const newPost = new this.postModel({
      content: createPostDto.content,
      mediaUrls: createPostDto.mediaUrls,
      author: user._id,
      group: createPostDto.groupId,
      visibility: createPostDto.visibility || 'PUBLIC',
      moderationStatus: isVideoPost
        ? ModerationStatus.PROCESSING
        : ModerationStatus.APPROVED,
    });

    const savedPost = await newPost.save();

    await this.userService.receiveXP(30, 'createPost', user.id);
    if (isVideoPost && createPostDto.mediaUrls) {
      this.eventEmitter.emit('post.video.uploaded', {
        postId: savedPost._id,
        videoPath: createPostDto.mediaUrls[0],
      });
    }
    if (createPostDto.groupId) {
      await this.groupsService.addXpToMember(
        user._id.toString(),
        createPostDto.groupId,
        10,
      );
    }

    return savedPost.populate({ path: 'author', select: 'username avatar' });
  }

  async findAllForFeed(currentUser: UserDocument): Promise<Post[]> {
    const friendIds = currentUser.friends.map((friend) => friend._id);
    const followingIds = currentUser.following.map(
      (followedUser) => followedUser._id,
    );

    const relevantUserIds = [
      ...new Set([...friendIds, ...followingIds, currentUser._id]),
    ];

    return this.postModel
      .find({
        group: { $exists: false },
        $or: [
          {
            moderationStatus: ModerationStatus.APPROVED,
            visibility: PostVisibility.PUBLIC,
          },
          {
            author: { $in: relevantUserIds },
            moderationStatus: ModerationStatus.APPROVED,
            visibility: PostVisibility.FRIENDS_ONLY,
          },
          {
            author: currentUser._id,
            moderationStatus: ModerationStatus.APPROVED,
            visibility: PostVisibility.PRIVATE,
          },
        ],
      })
      .sort({ createdAt: -1 })
      .populate([
        { path: 'author', select: 'username avatar' },
        {
          path: 'repostOf',
          populate: { path: 'author', select: 'username avatar' },
        },
      ])
      .exec();
  }
  async findPostById(id: string): Promise<Post> {
    const post = await this.postModel
      .findById(id)
      .populate('author', 'username avatar')
      .populate({
        path: 'repostOf',
        populate: {
          path: 'author',
          select: 'username avatar',
        },
      })
      .exec();
    if (!post) {
      throw new NotFoundException('Không tìm thấy bài đăng');
    }
    return post;
  }

  async deletePost(
    postId: string,
    user: UserDocument,
  ): Promise<{ message: string }> {
    const post = await this.postModel
      .findById(postId)
      .populate('author')
      .populate('group');

    if (!post) {
      throw new NotFoundException('Không tìm thấy bài đăng.');
    }

    const isAuthor = post.author._id.toString() === user._id.toString();
    const isAdmin = user.globalRole === 'ADMIN';

    if (!isAuthor && !isAdmin) {
      throw new UnauthorizedException('Bạn không có quyền xóa bài đăng này.');
    }

    // If admin is deleting someone else's post, send notification
    if (isAdmin && !isAuthor) {
      await this.notificationsService.createNotification(
        post.author as UserDocument,
        user,
        NotificationType.POST_DELETED_BY_ADMIN,
        '/',
        'Bài viết của bạn đã bị xóa bởi quản trị viên',
      );
    }

    await this.postModel.findByIdAndDelete(postId);
    await this.commentModel.deleteMany({ post: postId });

    return { message: 'Xóa bài đăng thành công.' };
  }

  async addComment(
    postId: string,
    user: UserDocument,
    createCommentDto: CreateCommentDto,
  ): Promise<Comment> {
    const textModeration = await this.moderationService.checkText(
      createCommentDto.content,
    );
    if (textModeration.status === ModerationStatus.REJECTED) {
      throw new BadRequestException(
        `Bình luận của bạn không phù hợp: ${textModeration.reason}`,
      );
    }

    const post = (await this.findPostById(postId)) as PostDocument;
    const newComment = new this.commentModel({
      ...createCommentDto,
      author: user._id,
      post: postId,
      moderationStatus: ModerationStatus.APPROVED,
    });
    await this.userService.receiveXP(5, 'comment', user.id);
    post.commentCount += 1;
    await post.save();

    await this.notificationsService.createNotification(
      post.author as UserDocument,
      user,
      NotificationType.NEW_COMMENT,
      `/posts/${post._id}`,
    );

    const savedComment = await newComment.save();
    await savedComment.populate({ path: 'author', select: 'username avatar' });
    return savedComment;
  }

  async findCommentsByPost(postId: string): Promise<Comment[]> {
    return this.commentModel
      .find({ post: postId, moderationStatus: ModerationStatus.APPROVED })
      .populate('author', 'username avatar')
      .sort({ createdAt: 'asc' })
      .exec();
  }

  async toggleReaction(
    postId: string,
    user: UserDocument,
    reactToPostDto: ReactToPostDto,
  ): Promise<Post> {
    const post = await this.postModel.findById(postId);
    if (!post) {
      throw new NotFoundException('Không tìm thấy bài đăng');
    }

    const userId = user._id;
    const reactionType = reactToPostDto.type;
    const existingReactionIndex = post.reactions.findIndex(
      (reaction) => reaction.user.toString() === userId.toString(),
    );

    if (existingReactionIndex > -1) {
      if (post.reactions[existingReactionIndex].type === reactionType) {
        post.reactions.splice(existingReactionIndex, 1);
      } else {
        post.reactions[existingReactionIndex].type = reactionType;
      }
    } else {
      post.reactions.push({ user: user._id as any, type: reactionType });

      if (post.author.toString() !== user._id.toString()) {
        await this.notificationsService.createNotification(
          post.author as UserDocument,
          user,
          NotificationType.NEW_REACTION,
          `/posts/${post._id}`,
        );
      }
    }
    await this.userService.receiveXP(5, 'like', userId.toString());
    const updatedPost = await post.save();

    // FIX: Populate trực tiếp đối tượng vừa lưu để đảm bảo dữ liệu đầy đủ
    await updatedPost.populate([
      { path: 'author', select: 'username avatar' },
      {
        path: 'repostOf',
        populate: { path: 'author', select: 'username avatar' },
      },
    ]);

    return updatedPost;
  }

  async repost(
    originalPostId: string,
    user: UserDocument,
    repostDto: RepostDto,
  ): Promise<Post> {
    const originalPost = await this.postModel.findById(originalPostId);
    if (!originalPost) {
      throw new NotFoundException('Không tìm thấy bài đăng gốc.');
    }

    if (originalPost.repostOf) {
      throw new BadRequestException(
        'Không thể chia sẻ lại một bài đã được chia sẻ.',
      );
    }

    // Check if original post is private
    if (originalPost.visibility === PostVisibility.PRIVATE) {
      throw new BadRequestException('Không thể chia sẻ bài viết riêng tư.');
    }

    // Check if original post is friends only and user is not friend
    if (originalPost.visibility === PostVisibility.FRIENDS_ONLY) {
      const isFriend = user.friends.some(
        (friendId) => friendId.toString() === originalPost.author.toString(),
      );

      if (!isFriend && originalPost.author.toString() !== user._id.toString()) {
        throw new BadRequestException(
          'Bạn không thể chia sẻ bài viết không thuộc bạn bè.',
        );
      }
    }

    const newRepost = new this.postModel({
      author: user._id,
      content: repostDto.content || '',
      repostOf: originalPostId,
      mediaUrls: [],
      moderationStatus: ModerationStatus.APPROVED,
      visibility: repostDto.visibility || PostVisibility.FRIENDS_ONLY,
    });

    const savedRepost = await newRepost.save();

    originalPost.repostCount = (originalPost.repostCount || 0) + 1;
    await originalPost.save();

    await savedRepost.populate([
      { path: 'author', select: 'username avatar' },
      {
        path: 'repostOf',
        populate: { path: 'author', select: 'username avatar' },
      },
    ]);

    return savedRepost;
  }

  async findPostsByAuthor(authorId: string): Promise<Post[]> {
    return this.postModel
      .find({ author: authorId, moderationStatus: ModerationStatus.APPROVED })
      .sort({ createdAt: -1 })
      .populate('author', 'username avatar')
      .populate({
        path: 'repostOf',
        populate: {
          path: 'author',
          select: 'username avatar',
        },
      })
      .exec();
  }

  async updatePost(
    postId: string,
    user: UserDocument,
    updatePostDto: UpdatePostDto,
  ): Promise<Post> {
    const post = await this.postModel.findById(postId);
    if (!post) {
      throw new NotFoundException('Không tìm thấy bài đăng.');
    }
    if (post.author.toString() !== user._id.toString()) {
      throw new UnauthorizedException(
        'Bạn không có quyền chỉnh sửa bài đăng này.',
      );
    }

    if (updatePostDto.content !== undefined) {
      post.content = updatePostDto.content;
    }

    // Chỉ cập nhật visibility nếu không phải bài viết trong nhóm
    if (updatePostDto.visibility !== undefined && !(post as any).group) {
      post.visibility = updatePostDto.visibility;
    }

    const updatedPost = await post.save();

    await updatedPost.populate([
      { path: 'author', select: 'username avatar' },
      {
        path: 'repostOf',
        populate: { path: 'author', select: 'username avatar' },
      },
      { path: 'group', select: 'name' }, // Thêm populate cho group nếu cần
    ]);
    return updatedPost;
  }
  async updateComment(
    commentId: string,
    user: UserDocument,
    updateCommentDto: UpdateCommentDto,
  ): Promise<Comment> {
    const comment = await this.commentModel.findById(commentId);
    if (!comment) {
      throw new NotFoundException('Không tìm thấy bình luận.');
    }
    if (comment.author.toString() !== user._id.toString()) {
      throw new UnauthorizedException(
        'Bạn không có quyền chỉnh sửa bình luận này.',
      );
    }

    comment.content = updateCommentDto.content;
    const savedComment = await comment.save();
    await savedComment.populate({ path: 'author', select: 'username avatar' });
    return savedComment;
  }

  // ✅ BỔ SUNG PHẦN CÒN THIẾU VÀO ĐÂY
  // ✅ HÀM DÀNH RIÊNG CHO TRANG NHÓM
  async findAllByGroup(groupId: string): Promise<Post[]> {
    return this.postModel
      .find({
        // Chỉ lấy các bài viết có groupId khớp
        group: groupId,
        moderationStatus: {
          $in: [ModerationStatus.APPROVED, ModerationStatus.PROCESSING],
        },
      })
      .sort({ createdAt: -1 })
      .populate('author', 'username avatar') // <-- Đã sửa thành avatar
      .populate({
        path: 'repostOf',
        populate: { path: 'author', select: 'username avatar' },
      })
      .exec();
  }
}
