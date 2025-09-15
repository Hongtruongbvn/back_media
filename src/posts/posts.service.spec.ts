import { Test, TestingModule } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { PostsService } from './posts.service';
import { Post, PostDocument } from './schemas/post.schema';
import { Comment, CommentDocument } from './schemas/comment.schema';
import { NotificationsService } from '../notifications/notifications.service';
import { GroupsService } from '../groups/groups.service';
import { ModerationService } from '../moderation/moderation.service';
import { UsersService } from '../users/users.service';
import { UserDocument } from '../auth/schemas/user.schema';
import { CreatePostDto } from './dto/create-post.dto';
import { CreateCommentDto } from './dto/create-comment.dto';
import { ReactToPostDto } from './dto/react-to-post.dto';
import { RepostDto } from './dto/repost.dto';
import { UpdatePostDto } from './dto/update-post.dto';
import { UpdateCommentDto } from './dto/update-comment.dto';
import {
  ModerationStatus,
  PostVisibility,
  ReactionType,
} from './schemas/post.schema';
import {
  NotFoundException,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { Types } from 'mongoose';

// Mock user data
const mockUserId = new Types.ObjectId();
const mockPostId = new Types.ObjectId();
const mockCommentId = new Types.ObjectId();

const mockUser = {
  _id: mockUserId,
  id: mockUserId.toString(),
  username: 'testuser',
  avatar: 'avatar.jpg',
  friends: [],
  following: [],
  save: jest.fn(),
} as unknown as UserDocument;

// Factory functions để tạo mock objects
const createMockPost = (overrides = {}) =>
  ({
    _id: mockPostId,
    id: mockPostId.toString(),
    author: { _id: mockUserId, username: 'testuser', avatar: 'avatar.jpg' },
    content: 'Test post content',
    mediaUrls: [],
    moderationStatus: ModerationStatus.APPROVED,
    commentCount: 0,
    repostCount: 0,
    visibility: PostVisibility.PUBLIC,
    reactions: [],
    save: jest.fn().mockResolvedValue({
      _id: mockPostId,
      author: { _id: mockUserId, username: 'testuser', avatar: 'avatar.jpg' },
      populate: jest.fn().mockResolvedValue({
        _id: mockPostId,
        author: { _id: mockUserId, username: 'testuser', avatar: 'avatar.jpg' },
      }),
    }),
    populate: jest.fn().mockResolvedValue({
      _id: mockPostId,
      author: { _id: mockUserId, username: 'testuser', avatar: 'avatar.jpg' },
    }),
    ...overrides,
  }) as unknown as PostDocument;

const createMockComment = (overrides = {}) =>
  ({
    _id: mockCommentId,
    id: mockCommentId.toString(),
    author: { _id: mockUserId, username: 'testuser', avatar: 'avatar.jpg' },
    post: { _id: mockPostId },
    content: 'Test comment',
    moderationStatus: ModerationStatus.APPROVED,
    replyCount: 0,
    save: jest.fn().mockResolvedValue({
      _id: mockCommentId,
      author: { _id: mockUserId, username: 'testuser', avatar: 'avatar.jpg' },
      populate: jest.fn().mockResolvedValue({
        _id: mockCommentId,
        author: { _id: mockUserId, username: 'testuser', avatar: 'avatar.jpg' },
      }),
    }),
    populate: jest.fn().mockResolvedValue({
      _id: mockCommentId,
      author: { _id: mockUserId, username: 'testuser', avatar: 'avatar.jpg' },
    }),
    ...overrides,
  }) as unknown as CommentDocument;

// Mock objects với constructor functions
const createMockPostModel = () => {
  const mockInstanceMethods = {
    save: jest.fn(),
    populate: jest.fn().mockResolvedValue(createMockPost()),
  };

  const mockStaticMethods = {
    find: jest.fn().mockReturnThis(),
    findById: jest.fn().mockReturnThis(),
    findOne: jest.fn().mockReturnThis(),
    create: jest.fn(),
    findByIdAndUpdate: jest.fn().mockReturnThis(),
    findByIdAndDelete: jest.fn().mockReturnThis(),
    deleteMany: jest.fn().mockResolvedValue({}),
    populate: jest.fn().mockReturnThis(),
    sort: jest.fn().mockReturnThis(),
    exec: jest.fn(),
  };

  const constructor = jest.fn().mockImplementation((data) => ({
    ...data,
    _id: mockPostId,
    save: mockInstanceMethods.save.mockResolvedValue(createMockPost(data)),
    populate: mockInstanceMethods.populate,
  }));

  return Object.assign(constructor, mockStaticMethods, mockInstanceMethods);
};

const createMockCommentModel = () => {
  const mockInstanceMethods = {
    save: jest.fn(),
    populate: jest.fn().mockResolvedValue(createMockComment()),
  };

  const mockStaticMethods = {
    find: jest.fn().mockReturnThis(),
    findById: jest.fn().mockReturnThis(),
    findOne: jest.fn().mockReturnThis(),
    create: jest.fn(),
    findByIdAndUpdate: jest.fn().mockReturnThis(),
    findByIdAndDelete: jest.fn().mockReturnThis(),
    deleteMany: jest.fn().mockResolvedValue({}),
    populate: jest.fn().mockReturnThis(),
    sort: jest.fn().mockReturnThis(),
    exec: jest.fn(),
  };

  const constructor = jest.fn().mockImplementation((data) => ({
    ...data,
    _id: mockCommentId,
    save: mockInstanceMethods.save.mockResolvedValue(createMockComment(data)),
    populate: mockInstanceMethods.populate,
  }));

  return Object.assign(constructor, mockStaticMethods, mockInstanceMethods);
};

const mockNotificationsService = {
  createNotification: jest.fn().mockResolvedValue({}),
};

const mockGroupsService = {
  addXpToMember: jest.fn().mockResolvedValue({}),
};

const mockModerationService = {
  checkText: jest.fn().mockResolvedValue({
    status: ModerationStatus.APPROVED,
  }),
};

const mockUsersService = {
  receiveXP: jest.fn().mockResolvedValue({}),
};

const mockEventEmitter = {
  emit: jest.fn(),
};

describe('PostsService', () => {
  let service: PostsService;
  let mockPost: PostDocument;
  let mockComment: CommentDocument;
  let mockPostModel: any;
  let mockCommentModel: any;

  beforeEach(async () => {
    // Tạo instances mới cho mỗi test
    mockPost = createMockPost();
    mockComment = createMockComment();

    // Tạo mock models mới
    mockPostModel = createMockPostModel();
    mockCommentModel = createMockCommentModel();

    // Reset all mocks
    jest.clearAllMocks();

    // Cấu hình mock returns
    mockPostModel.exec.mockResolvedValue([mockPost]);
    mockCommentModel.exec.mockResolvedValue([mockComment]);

    mockPostModel.findById.mockReturnValue({
      populate: jest.fn().mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockPost),
      }),
    });

    mockCommentModel.findById.mockReturnValue({
      populate: jest.fn().mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockComment),
      }),
    });

    mockPostModel.create.mockImplementation(() => mockPost);
    mockCommentModel.create.mockImplementation(() => mockComment);

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PostsService,
        {
          provide: getModelToken(Post.name),
          useValue: mockPostModel,
        },
        {
          provide: getModelToken(Comment.name),
          useValue: mockCommentModel,
        },
        {
          provide: NotificationsService,
          useValue: mockNotificationsService,
        },
        {
          provide: GroupsService,
          useValue: mockGroupsService,
        },
        {
          provide: ModerationService,
          useValue: mockModerationService,
        },
        {
          provide: UsersService,
          useValue: mockUsersService,
        },
        {
          provide: EventEmitter2,
          useValue: mockEventEmitter,
        },
      ],
    }).compile();

    service = module.get<PostsService>(PostsService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createPost', () => {
    it('should create a new post successfully', async () => {
      const createPostDto: CreatePostDto = {
        content: 'Test post content',
        mediaUrls: [],
        visibility: PostVisibility.PUBLIC,
      };

      mockModerationService.checkText.mockResolvedValue({
        status: ModerationStatus.APPROVED,
      });

      // Mock the save method to return a post with populate method
      const mockSavedPost = createMockPost();
      mockPostModel.save.mockResolvedValue(mockSavedPost);

      const result = await service.createPost(mockUser, createPostDto);

      expect(result).toBeDefined();
      expect(mockModerationService.checkText).toHaveBeenCalledWith(
        createPostDto.content,
      );
      expect(mockUsersService.receiveXP).toHaveBeenCalledWith(
        30,
        'createPost',
        mockUser.id,
      );
    });

    it('should throw BadRequestException if content is rejected by moderation', async () => {
      const createPostDto: CreatePostDto = {
        content: 'Inappropriate content',
        mediaUrls: [],
      };

      mockModerationService.checkText.mockResolvedValue({
        status: ModerationStatus.REJECTED,
        reason: 'Inappropriate language',
      });

      await expect(service.createPost(mockUser, createPostDto)).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('findAllForFeed', () => {
    it('should return posts for feed', async () => {
      mockPostModel.find.mockReturnValue({
        sort: jest.fn().mockReturnValue({
          populate: jest.fn().mockReturnValue({
            exec: jest.fn().mockResolvedValue([mockPost]),
          }),
        }),
      });

      const result = await service.findAllForFeed(mockUser);

      expect(result).toEqual([mockPost]);
      expect(mockPostModel.find).toHaveBeenCalled();
    });
  });

  describe('addComment', () => {
    it('should add a comment to a post', async () => {
      const createCommentDto: CreateCommentDto = {
        content: 'Test comment',
      };

      mockModerationService.checkText.mockResolvedValue({
        status: ModerationStatus.APPROVED,
      });

      // Mock findPostById to return a post
      jest.spyOn(service, 'findPostById').mockResolvedValue(mockPost as any);

      const result = await service.addComment(
        mockPostId.toString(),
        mockUser,
        createCommentDto,
      );

      expect(result).toBeDefined();
      expect(mockModerationService.checkText).toHaveBeenCalledWith(
        createCommentDto.content,
      );
      expect(mockUsersService.receiveXP).toHaveBeenCalledWith(
        5,
        'comment',
        mockUser.id,
      );
    });
  });

  describe('toggleReaction', () => {
    it('should add a reaction to a post', async () => {
      const reactToPostDto: ReactToPostDto = {
        type: ReactionType.LIKE,
      };

      const postWithNoReactions = createMockPost({
        reactions: [],
        save: jest.fn().mockResolvedValue(mockPost),
      });

      mockPostModel.findById.mockResolvedValue(postWithNoReactions);

      const result = await service.toggleReaction(
        mockPostId.toString(),
        mockUser,
        reactToPostDto,
      );

      expect(result).toBeDefined();
      expect(mockUsersService.receiveXP).toHaveBeenCalledWith(
        5,
        'like',
        mockUser._id.toString(),
      );
    });

    it('should remove a reaction if already exists', async () => {
      const reactToPostDto: ReactToPostDto = {
        type: ReactionType.LIKE,
      };

      const postWithReaction = createMockPost({
        reactions: [{ user: mockUser._id, type: ReactionType.LIKE }],
        save: jest.fn().mockResolvedValue(mockPost),
      });

      mockPostModel.findById.mockResolvedValue(postWithReaction);

      const result = await service.toggleReaction(
        mockPostId.toString(),
        mockUser,
        reactToPostDto,
      );

      expect(result).toBeDefined();
    });
  });

  describe('repost', () => {
    it('should create a repost successfully', async () => {
      const repostDto: RepostDto = {
        content: 'Repost content',
        visibility: PostVisibility.FRIENDS_ONLY,
      };

      mockPostModel.findById.mockResolvedValue(mockPost);

      const result = await service.repost(
        mockPostId.toString(),
        mockUser,
        repostDto,
      );

      expect(result).toBeDefined();
      expect(mockPostModel.findById).toHaveBeenCalledWith(
        mockPostId.toString(),
      );
    });

    it('should throw NotFoundException if original post not found', async () => {
      mockPostModel.findById.mockResolvedValue(null);

      await expect(
        service.repost('invalid-id', mockUser, {} as RepostDto),
      ).rejects.toThrow(NotFoundException);
    });
  });

describe('updatePost', () => {
  it('should update a post successfully', async () => {
    const updatePostDto: UpdatePostDto = {
      content: 'Updated content',
    };

    // Tạo post với author trùng với mockUser
    const postWithSameAuthor = createMockPost({
      author: {
        _id: mockUserId,
        toString: () => mockUserId.toString(),
      },
    });

    mockPostModel.findById.mockResolvedValue(postWithSameAuthor);

    const result = await service.updatePost(
      mockPostId.toString(),
      mockUser,
      updatePostDto,
    );

    expect(result).toBeDefined();
    expect(mockPostModel.findById).toHaveBeenCalledWith(mockPostId.toString());
  });

  it('should throw UnauthorizedException if user is not author', async () => {
    const differentUserId = new Types.ObjectId();
    const differentUser = {
      ...mockUser,
      _id: differentUserId,
      id: differentUserId.toString(),
    } as unknown as UserDocument;

    const postWithDifferentAuthor = createMockPost({
      author: {
        _id: new Types.ObjectId(),
        toString: () => new Types.ObjectId().toString(),
      },
    });

    mockPostModel.findById.mockResolvedValue(postWithDifferentAuthor);

    await expect(
      service.updatePost(
        mockPostId.toString(),
        differentUser,
        {} as UpdatePostDto,
      ),
    ).rejects.toThrow(UnauthorizedException);
  });
});

  describe('replyComment', () => {
    it('should reply to a comment successfully', async () => {
      const createCommentDto: CreateCommentDto = {
        content: 'Reply comment',
      };

      mockCommentModel.findById.mockResolvedValue(mockComment);
      mockModerationService.checkText.mockResolvedValue({
        status: ModerationStatus.APPROVED,
      });

      const result = await service.replyComment(
        mockCommentId.toString(),
        mockUser,
        createCommentDto,
      );

      expect(result).toBeDefined();
      expect(mockUsersService.receiveXP).toHaveBeenCalledWith(
        3,
        'reply',
        mockUser.id,
      );
    });

    it('should throw NotFoundException if parent comment not found', async () => {
      mockCommentModel.findById.mockResolvedValue(null);

      await expect(
        service.replyComment('invalid-id', mockUser, {} as CreateCommentDto),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('deleteComment', () => {
    it('should delete a comment successfully', async () => {
      mockCommentModel.findById.mockResolvedValue(mockComment);
      mockCommentModel.findByIdAndDelete.mockResolvedValue(mockComment);
      mockPostModel.findByIdAndUpdate.mockResolvedValue(mockPost);

      const result = await service.deleteComment(mockCommentId.toString());

      expect(result).toBeDefined();
      expect(mockCommentModel.findByIdAndDelete).toHaveBeenCalledWith(
        mockCommentId.toString(),
      );
    });
  });

  describe('getCommentReplies', () => {
    it('should get replies for a comment', async () => {
      mockCommentModel.find.mockReturnValue({
        populate: jest.fn().mockReturnValue({
          sort: jest.fn().mockReturnValue({
            exec: jest.fn().mockResolvedValue([mockComment]),
          }),
        }),
      });

      const result = await service.getCommentReplies(mockCommentId.toString());

      expect(result).toEqual([mockComment]);
      expect(mockCommentModel.find).toHaveBeenCalledWith({
        parentComment: mockCommentId.toString(),
        moderationStatus: ModerationStatus.APPROVED,
      });
    });
  });

  describe('findPostsByAuthor', () => {
    it('should find posts by author', async () => {
      mockPostModel.find.mockReturnValue({
        sort: jest.fn().mockReturnValue({
          populate: jest.fn().mockReturnValue({
            populate: jest.fn().mockReturnValue({
              exec: jest.fn().mockResolvedValue([mockPost]),
            }),
          }),
        }),
      });

      const result = await service.findPostsByAuthor(mockUserId.toString());

      expect(result).toEqual([mockPost]);
      expect(mockPostModel.find).toHaveBeenCalledWith({
        author: mockUserId.toString(),
        moderationStatus: ModerationStatus.APPROVED,
      });
    });
  });

  describe('findAllByGroup', () => {
    it('should find posts by group', async () => {
      mockPostModel.find.mockReturnValue({
        sort: jest.fn().mockReturnValue({
          populate: jest.fn().mockReturnValue({
            populate: jest.fn().mockReturnValue({
              exec: jest.fn().mockResolvedValue([mockPost]),
            }),
          }),
        }),
      });

      const result = await service.findAllByGroup('group123');

      expect(result).toEqual([mockPost]);
      expect(mockPostModel.find).toHaveBeenCalledWith({
        group: 'group123',
        moderationStatus: {
          $in: [ModerationStatus.APPROVED, ModerationStatus.PROCESSING],
        },
      });
    });
  });
});
