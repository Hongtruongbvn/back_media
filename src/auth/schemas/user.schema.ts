import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document, Types } from 'mongoose';
import { Interest } from '../../interests/schemas/interest.schema';
import { ShopItem } from '../../shop/schemas/shop-item.schema';

export enum GlobalRole {
  USER = 'USER',
  MODERATOR = 'MODERATOR',
  ADMIN = 'ADMIN',
}

export enum AccountType {
  FREE = 'FREE',
  PREMIUM = 'PREMIUM',
}

export enum PresenceStatus {
  ONLINE = 'ONLINE',
  OFFLINE = 'OFFLINE',
}

export enum AccountStatus {
  ACTIVE = 'ACTIVE',
  SUSPENDED = 'SUSPENDED',
  BANNED = 'BANNED',
}

export type UserDocument = User & Document & { _id: Types.ObjectId };

@Schema({ _id: false })
export class Warning {
  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    default: () => new Types.ObjectId(),
  })
  _id: Types.ObjectId;

  @Prop({ required: true })
  reason: string;

  @Prop({ required: true, default: Date.now })
  date: Date;

  @Prop({ required: true, type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  by: Types.ObjectId;
}
const WarningSchema = SchemaFactory.createForClass(Warning);

@Schema({ _id: false }) // _id: false để không tạo _id cho schema con này
export class GameStatus {
  @Prop({ enum: GlobalRole, default: GlobalRole.USER })
  globalRole: GlobalRole;

  @Prop()
  igdbId: string;

  @Prop()
  name: string;

  @Prop()
  boxArtUrl: string;
}

@Schema({ timestamps: true })
export class User {
  _id: mongoose.Schema.Types.ObjectId;
  @Prop({ enum: GlobalRole, default: GlobalRole.USER })
  globalRole: GlobalRole;

  @Prop({ enum: AccountStatus, default: AccountStatus.ACTIVE })
  accountStatus: AccountStatus;

  @Prop()
  suspensionExpires?: Date;

  @Prop({ type: [WarningSchema], default: [] })
  warnings: Warning[];

  @Prop({ enum: PresenceStatus, default: PresenceStatus.ONLINE })
  presenceStatus: PresenceStatus;

  @Prop({ required: true, unique: true, trim: true, index: true })
  username: string;

  @Prop({ required: true, unique: true, trim: true, index: true })
  email: string;

  @Prop({ required: true, select: false }) // Thêm select: false để không trả về password trong các query
  password: string;

  @Prop({ default: 'default_avatar.png' })
  avatar: string;

  @Prop()
  birthday: Date;

  @Prop({ default: '' })
  bio: string;

  @Prop({ default: 'default_cover.png' })
  coverImage: string;

  @Prop({ type: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }] })
  followers: User[];

  @Prop({ type: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }] })
  following: User[];

  @Prop({ type: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Interest' }] })
  interests: Interest[];

  @Prop({ enum: AccountType, default: AccountType.FREE })
  accountType: AccountType;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ShopItem',
    required: false,
  })
  equippedAvatarFrame?: ShopItem;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ShopItem',
    required: false,
  })
  equippedProfileBackground?: ShopItem;

  // --- BỔ SUNG CÁC Ô TRANG BỊ MỚI ---
  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ShopItem',
    required: false,
  })
  equippedProfileEffect?: ShopItem;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ShopItem',
    required: false,
  })
  equippedAvatarDecoration?: ShopItem;

  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ShopItem',
    required: false,
  })
  equippedNameplateTheme?: ShopItem;

  @Prop({ type: GameStatus, required: false })
  currentGame?: GameStatus;

  @Prop({ default: false })
  isEmailVerified: boolean;

  @Prop()
  passwordResetToken?: string;

  @Prop()
  passwordResetExpires?: Date;

  @Prop({ type: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }] })
  friends: User[]; // Danh sách bạn bè

  @Prop({ type: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }] })
  blockedUsers: User[];

  @Prop({ default: false })
  hasSelectedInterests: boolean;

  // --- BỔ SUNG TRƯỜNG TIỀN TỆ ---
  @Prop({ type: Number, default: 100 }) // Tặng 100 coins cho người dùng mới
  coins: number;

  @Prop({ default: 0 })
  xp_per_day: number;
  @Prop({ default: 0 })
  xp: number;

  @Prop({ type: [Number], default: [] })
  milestonesReached: number[];
}

export const UserSchema = SchemaFactory.createForClass(User);
