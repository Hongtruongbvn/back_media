import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Schema as MSchema, Types } from 'mongoose';

export type GroupInviteDocument = HydratedDocument<GroupInvite>;

export type GroupInviteStatus = 'PENDING'|'ACCEPTED'|'DECLINED'|'CANCELED';

@Schema({ timestamps: true, collection: 'group_invites' })
export class GroupInvite {
  @Prop({ type: MSchema.Types.ObjectId, ref: 'Group', required: true })
  group: Types.ObjectId;

  @Prop({ type: MSchema.Types.ObjectId, ref: 'User', required: true })
  inviter: Types.ObjectId;

  @Prop({ type: MSchema.Types.ObjectId, ref: 'User', required: true })
  invitee: Types.ObjectId;

  @Prop({ type: String, enum: ['PENDING','ACCEPTED','DECLINED','CANCELED'], default: 'PENDING' })
  status: GroupInviteStatus;
}

export const GroupInviteSchema = SchemaFactory.createForClass(GroupInvite);

// 🔐 Index tránh trùng lời mời PENDING trong cùng group cho cùng invitee
GroupInviteSchema.index(
  { group: 1, invitee: 1, status: 1 },
  { unique: true, partialFilterExpression: { status: 'PENDING' } }
);
