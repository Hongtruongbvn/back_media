import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Story, StoryDocument } from './schemas/story.schema';
import { UserDocument } from '../auth/schemas/user.schema';

@Injectable()
export class StoriesService {
    constructor(@InjectModel(Story.name) private storyModel: Model<StoryDocument>) {}

    async createStory(author: UserDocument, mediaUrl: string, mediaType: 'IMAGE' | 'VIDEO'): Promise<Story> {
        const newStory = new this.storyModel({ author: author._id, mediaUrl, mediaType });
        return newStory.save();
    }

    async findActiveStories(user: UserDocument): Promise<Story[]> {
        const followingIds = user.following;
        return this.storyModel.find({ author: { $in: followingIds } }).populate('author', 'username avatar').sort({ createdAt: -1 });
    }
}
