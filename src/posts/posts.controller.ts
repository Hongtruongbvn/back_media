import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Delete,
  Patch,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { PostsService } from './posts.service';
import { CreatePostDto } from './dto/create-post.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';
import { UserDocument } from '../auth/schemas/user.schema';
import { CreateCommentDto } from './dto/create-comment.dto';
import { ReactToPostDto } from './dto/react-to-post.dto';
import { RepostDto } from './dto/repost.dto';
import { UpdatePostDto } from './dto/update-post.dto';
import { UpdateCommentDto } from './dto/update-comment.dto';

@Controller('posts')
export class PostsController {
  constructor(private readonly postsService: PostsService) {}

  // --- CÁC ROUTE CỤ THỂ (KHÔNG CÓ THAM SỐ) ĐƯỢC ĐẶT LÊN ĐẦU ---

  @UseGuards(JwtAuthGuard)
  @Post()
  create(@GetUser() user: UserDocument, @Body() createPostDto: CreatePostDto) {
    return this.postsService.createPost(user, createPostDto);
  }

  @Get('feed')
  @UseGuards(JwtAuthGuard)
  async getForFeed(@GetUser() user: UserDocument) {
    const posts = await this.postsService.findAllForFeed(user);
    console.log('Số bài viết trả về:', posts.length); // Debug log
    return posts;
  }

  // --- CÁC ROUTE CÓ THAM SỐ NHƯNG CỤ THỂ ---

  @Get('group/:groupId')
  @UseGuards(JwtAuthGuard)
  findAllByGroup(@Param('groupId') groupId: string) {
    return this.postsService.findAllByGroup(groupId);
  }

  @Get('user/:authorId')
  findPostsByAuthor(@Param('authorId') authorId: string) {
    return this.postsService.findPostsByAuthor(authorId);
  }

  @UseGuards(JwtAuthGuard)
  @Patch('comments/:id')
  updateComment(
    @Param('id') commentId: string,
    @GetUser() user: UserDocument,
    @Body() updateCommentDto: UpdateCommentDto,
  ) {
    return this.postsService.updateComment(commentId, user, updateCommentDto);
  }

  @UseGuards(JwtAuthGuard)
  @Delete('comments/:id')
  deleteComment(@Param('id') id: string) {
    return this.postsService.deleteComment(id);
  }

  // --- CÁC ROUTE CHUNG CHUNG (CÓ THAM SỐ :id) ĐƯỢC ĐẶT XUỐNG DƯỚI ---

  @Get(':id') // Route này sẽ chỉ được dùng khi các route ở trên không khớp
  findOne(@Param('id') id: string) {
    return this.postsService.findPostById(id);
  }

  @UseGuards(JwtAuthGuard)
  @Delete(':id')
  remove(@Param('id') id: string, @GetUser() user: UserDocument) {
    return this.postsService.deletePost(id, user);
  }

  @UseGuards(JwtAuthGuard)
  @Post(':id/comments')
  addComment(
    @Param('id') postId: string,
    @GetUser() user: UserDocument,
    @Body() createCommentDto: CreateCommentDto,
  ) {
    return this.postsService.addComment(postId, user, createCommentDto);
  }

  @Get(':id/comments')
  findComments(@Param('id') postId: string) {
    return this.postsService.findCommentsByPost(postId);
  }

  @UseGuards(JwtAuthGuard)
  @Post(':id/react')
  @HttpCode(HttpStatus.OK)
  toggleReaction(
    @Param('id') postId: string,
    @GetUser() user: UserDocument,
    @Body() reactToPostDto: ReactToPostDto,
  ) {
    return this.postsService.toggleReaction(postId, user, reactToPostDto);
  }

  @UseGuards(JwtAuthGuard)
  @Post(':id/repost')
  async repost(
    @Param('id') originalPostId: string,
    @GetUser() user: UserDocument,
    @Body() repostDto: RepostDto,
  ) {
    return this.postsService.repost(originalPostId, user, repostDto);
  }

  @UseGuards(JwtAuthGuard)
  @Patch(':id')
  updatePost(
    @Param('id') postId: string,
    @GetUser() user: UserDocument,
    @Body() updatePostDto: UpdatePostDto,
  ) {
    return this.postsService.updatePost(postId, user, updatePostDto);
  }
  @UseGuards(JwtAuthGuard)
  @Post('comments/:id/replies')
  async replyComment(
    @Param('id') parentCommentId: string,
    @GetUser() user: UserDocument,
    @Body() createCommentDto: CreateCommentDto,
  ) {
    return this.postsService.replyComment(
      parentCommentId,
      user,
      createCommentDto,
    );
  }

  @Get('comments/:id/replies')
  async getCommentReplies(@Param('id') commentId: string) {
    return this.postsService.getCommentReplies(commentId);
  }

  @UseGuards(JwtAuthGuard)
  @Get(':id/comment-count')
  async getCommentCount(@Param('id') postId: string) {
    const post = await this.postsService.findPostById(postId);
    return { commentCount: post.commentCount };
  }
}
