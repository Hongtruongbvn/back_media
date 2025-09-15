import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from '../auth/schemas/user.schema';
import { Post, PostDocument } from '../posts/schemas/post.schema';
import { Group, GroupDocument } from '../groups/schemas/group.schema';

@Injectable()
export class SearchService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    @InjectModel(Post.name) private postModel: Model<PostDocument>,
    @InjectModel(Group.name) private groupModel: Model<GroupDocument>,
  ) {}

  // ✅ HÀM NÀY ĐÃ ĐƯỢC NÂNG CẤP HOÀN CHỈNH
  async searchAll(query: string) {
    if (!query || query.trim().length < 2) {
      return []; // Vẫn giữ: chỉ tìm khi có ít nhất 2 ký tự
    }

    // --- BƯỚC 1: Xử lý chuỗi tìm kiếm an toàn ---
    // Chuyển các ký tự đặc biệt của regex thành ký tự thường
    const escapeRegex = (text: string) => {
      return text.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
    };
    const safeQuery = escapeRegex(query.trim());
    const regex = new RegExp(safeQuery, 'i'); // 'i' để không phân biệt hoa thường

    // --- BƯỚC 2: Tìm kiếm song song trên cả 3 bảng ---
    const [users, posts, groups] = await Promise.all([
      // Tìm người dùng
      this.userModel.find({ username: regex })
        .limit(5)
        .select('username avatar')
        .lean(),
      
      // Tìm bài viết (chỉ bài công khai, không thuộc nhóm)
      this.postModel.find({ content: regex, group: { $exists: false }, visibility: 'PUBLIC' })
        .limit(5)
        .select('content author')
        .populate('author', 'username avatar')
        .lean(),
        
      // Tìm nhóm (chỉ nhóm công khai)
      this.groupModel.find({ name: regex, privacy: 'public' })
        .limit(5)
        .select('name avatar memberCount')
        .lean(),
    ]);

    // --- BƯỚC 3: Chuẩn hóa và gộp kết quả ---
    const formattedUsers = users.map(user => ({
      _id: user._id,
      name: user.username,
      username: user.username,
      avatar: user.avatar,
      type: 'user' as const,
    }));

    const formattedPosts = posts.map(post => ({
      _id: post._id,
      name: `Bài viết của ${post.author.username}: "${post.content.substring(0, 30)}..."`,
      avatar: post.author.avatar,
      type: 'post' as const,
    }));

    const formattedGroups = groups.map(group => ({
      _id: group._id,
      name: group.name,
      avatar: group.avatar,
      type: 'group' as const,
    }));

    return [...formattedUsers, ...formattedGroups, ...formattedPosts];
  }
}