// File: api/src/chat/chat.gateway.ts
import {
  SubscribeMessage,
  WebSocketGateway,
  OnGatewayInit,
  WebSocketServer,
  OnGatewayConnection,
  OnGatewayDisconnect,
} from '@nestjs/websockets';
import { Logger, Inject, forwardRef } from '@nestjs/common';
import { Socket, Server } from 'socket.io';
import { ChatService } from './chat.service';
import { ChatbotService } from '../chatbot/chatbot.service';
import { ConfigService } from '@nestjs/config';
import { PresenceService } from '../presence/presence.service';
import { BlockService } from '../block/block.service';

@WebSocketGateway({ cors: { origin: '*' } })
export class ChatGateway implements OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect {
  private chatbotUserId: string;
  private isSendingMessage = false;

  // ===== Typing state (TTL) =====
  private typingTimers = new Map<string, Map<string, NodeJS.Timeout>>(); // roomId -> (userId -> timeout)
  private typingState  = new Map<string, Map<string, { id: string; username: string }>>(); // roomId -> (userId -> user)
  private static readonly TYPING_TTL_MS = 3500;

  // ===== Presence (RAM) =====
  private socketsByUser = new Map<string, Set<string>>(); // userId -> Set<socketId>
  private lastSeenByUser = new Map<string, number>();     // userId -> lastSeen(ms)

  @WebSocketServer() server: Server;
  private logger: Logger = new Logger('ChatGateway');

  constructor(
    @Inject(forwardRef(() => ChatService))
    private chatService: ChatService,
    private chatbotService: ChatbotService,
    private configService: ConfigService,
    private presenceService: PresenceService,
    private blockService: BlockService,
  ) {
    const chatbotUserId = this.configService.get<string>('CHATBOT_USER_ID');
    if (!chatbotUserId) throw new Error('CHATBOT_USER_ID is not defined in configuration');
    this.chatbotUserId = chatbotUserId;
  }

  // Cho ChatService phát khi tạo phòng mới
  public broadcastRoomCreated(room: any) {
    this.server.emit('room_created', room);
  }

  // ===== Auth helpers =====
  private extractToken(client: Socket): string | null {
    const authToken = (client.handshake as any)?.auth?.token as string | undefined;
    const queryToken = (client.handshake as any)?.query?.token as string | undefined;
    const headerAuth = client.handshake.headers?.authorization as string | undefined;
    if (authToken) return authToken;
    if (queryToken) return queryToken;
    if (headerAuth) return headerAuth.startsWith('Bearer ') ? headerAuth.slice(7) : headerAuth;
    return null;
  }

  private async ensureUser(client: Socket) {
    if ((client.data as any)?.user) return (client.data as any).user;
    const token = this.extractToken(client);
    if (!token) throw new Error('No token');
    const user = await this.chatService.getUserFromSocket(token);
    (client.data as any).user = user;
    return user;
  }

  // ===== Typing helpers =====
  private clearTyping(roomId: string, userId: string) {
    const t = this.typingTimers.get(roomId)?.get(userId);
    if (t) clearTimeout(t);
    this.typingTimers.get(roomId)?.delete(userId);
    this.typingState.get(roomId)?.delete(userId);
  }
  private getTypers(roomId: string) {
    return Array.from(this.typingState.get(roomId)?.values() || []);
  }

  // ===== Presence helpers =====
  private setOnline(userId: string, socketId: string) {
    const set = this.socketsByUser.get(userId) ?? new Set<string>();
    set.add(socketId);
    this.socketsByUser.set(userId, set);

    // lần đầu online
    if (set.size === 1) {
      this.server.emit('presence_update', { userId, online: true });
      try {
        this.presenceService.addUser?.(userId, socketId);
        this.presenceService.setOnline?.(userId);
      } catch {}
    } else {
      try { this.presenceService.addUser?.(userId, socketId); } catch {}
    }
  }

  private setOffline(userId: string, socketId: string) {
    const set = this.socketsByUser.get(userId);
    if (!set) return;

    set.delete(socketId);
    if (set.size === 0) {
      this.socketsByUser.delete(userId);
      const ts = Date.now();
      this.lastSeenByUser.set(userId, ts);
      this.server.emit('presence_update', { userId, online: false, lastSeen: ts });
      try {
        // dọn registry & cập nhật DB
        this.presenceService.removeUserBySocketId?.(socketId);
        this.presenceService.setOffline?.(userId, ts);
      } catch {}
    } else {
      this.socketsByUser.set(userId, set);
      try { this.presenceService.removeUserBySocketId?.(socketId); } catch {}
    }
  }

  private buildSnapshot(ids: string[]) {
    const users: Record<string, { online: boolean; lastSeen?: number }> = {};
    ids.forEach((id) => {
      const online = (this.socketsByUser.get(id)?.size ?? 0) > 0;
      users[id] = { online, lastSeen: this.lastSeenByUser.get(id) };
    });
    return users;
  }

  // ===== Lifecycle =====
  afterInit() {
    this.logger.log('ChatGateway Initialized!');
  }

  async handleConnection(client: Socket) {
    this.logger.log(`Client connected to Chat: ${client.id}`);
    try {
      const user = await this.ensureUser(client);
      const uid = String(user._id);
      this.setOnline(uid, client.id);
    } catch (e) {
      this.logger.error('Chat Auth error', e);
      client.emit('error', { message: 'Unauthorized' });
      client.disconnect();
    }
  }

  handleDisconnect(client: Socket) {
    this.logger.log(`Client disconnected from Chat: ${client.id}`);
    const user: any = (client.data as any)?.user;
    if (user?._id) {
      const uid = String(user._id);
      this.setOffline(uid, client.id);
    }

    // clear typing ở các phòng đã join
    const rooms = Array.from(client.rooms).filter((r) => r !== client.id);
    rooms.forEach((roomId) => {
      if (user?._id) {
        this.clearTyping(roomId, String(user._id));
        this.server.to(roomId).emit('typing_list', { chatroomId: roomId, typers: this.getTypers(roomId) });
      }
    });
  }

  // ===== Rooms =====
  @SubscribeMessage('joinRoom')
  async handleJoinRoom(client: Socket, payload: { chatroomId: string }) {
    try {
      const user = await this.ensureUser(client);
      const chatroomId = payload?.chatroomId;
      if (!chatroomId) return client.emit('error', { message: 'chatroomId is required' });

      const ok = await this.chatService.isMemberOfRoom(user._id, chatroomId);
      if (!ok) return client.emit('error', { message: 'Not allowed' });

      await client.join(chatroomId);
      client.emit('joinedRoom', { chatroomId });
    } catch (e: any) {
      this.logger.error('joinRoom error', e);
      client.emit('error', { message: e?.message || 'Join room failed' });
    }
  }

  @SubscribeMessage('leaveRoom')
  async handleLeaveRoom(client: Socket, payload: { chatroomId: string }) {
    try {
      const chatroomId = payload?.chatroomId;
      if (!chatroomId) return client.emit('error', { message: 'chatroomId is required' });

      const user: any = (client.data as any)?.user;
      if (user?._id) {
        this.clearTyping(chatroomId, String(user._id));
        this.server.to(chatroomId).emit('typing_list', { chatroomId, typers: this.getTypers(chatroomId) });
      }
      await client.leave(chatroomId);
    } catch (e: any) {
      this.logger.error('leaveRoom error', e);
      client.emit('error', { message: e?.message || 'Leave room failed' });
    }
  }

  // ===== Send message (kèm chặn DM) =====
  @SubscribeMessage('sendMessage')
  async handleMessage(client: Socket, payload: { chatroomId: string; content: string }): Promise<void> {
    try {
      if (this.isSendingMessage) return;
      this.isSendingMessage = true;

      const user = await this.ensureUser(client);
      const chatroomId = payload?.chatroomId;
      const content = payload?.content ?? '';

      if (!chatroomId) { client.emit('error', { message: 'chatroomId is required' }); this.isSendingMessage = false; return; }
      if (!content.trim()) { client.emit('error', { message: 'Content is empty' }); this.isSendingMessage = false; return; }

      const allowed = await this.chatService.isMemberOfRoom(user._id, chatroomId);
      if (!allowed) { client.emit('error', { message: 'Not allowed' }); this.isSendingMessage = false; return; }

      // ---- Chặn DM nếu bị block
      const chatroom = await this.chatService.findRoomById(chatroomId);
      if (!chatroom) { this.isSendingMessage = false; return; }

      const isDM = !chatroom.isGroupChat && Array.isArray(chatroom.members) && chatroom.members.length <= 2;
      if (isDM) {
        const memberIds = chatroom.members.map((m: any) => String(m.user));
        const peerId = memberIds.find((id: string) => id !== String(user._id));
        if (peerId) {
          const blocked = await this.blockService.isBlockedEither(String(user._id), peerId);
          if (blocked) {
            client.emit('error', { message: 'blocked' });
            this.isSendingMessage = false;
            return;
          }
        }
      }

      const message = await this.chatService.createMessage(user, chatroomId, content);
      this.server.to(chatroomId).emit('newMessage', message);

      // Clear typing của người gửi
      this.clearTyping(chatroomId, String(user._id));
      this.server.to(chatroomId).emit('typing_list', { chatroomId, typers: this.getTypers(chatroomId) });

      // Chatbot (nếu có)
      if (chatroom?.members?.some(m => (m.user as any).toString?.() === this.chatbotUserId)) {
        const botContent = await this.chatbotService.getResponse(content);
        const botMsg = await this.chatService.createBotMessage(this.chatbotUserId, chatroomId, botContent);
        this.server.to(chatroomId).emit('newMessage', botMsg);
      }

      this.isSendingMessage = false;
    } catch (e: any) {
      this.logger.error('sendMessage error', e);
      client.emit('error', { message: e?.response?.message || e?.message || 'Send message failed' });
      this.isSendingMessage = false;
    }
  }

  // ===== Read status =====
  @SubscribeMessage('mark_room_as_read')
  async handleMarkAsRead(client: Socket, payload: { chatroomId: string }) {
    try {
      const user = await this.ensureUser(client);
      const chatroomId = payload?.chatroomId;
      if (!chatroomId) return client.emit('error', { message: 'chatroomId is required' });
      await this.chatService.markRoomAsRead(user._id, chatroomId);
      client.emit('room_marked_as_read', { chatroomId });
    } catch (e: any) {
      this.logger.error('mark_room_as_read error', e);
      client.emit('error', { message: e?.message || 'Mark read failed' });
    }
  }

  // ===== Typing events =====
  @SubscribeMessage('typing_ping')
  async onTypingPing(client: Socket, payload: { chatroomId: string; user: { id: string; username: string } }) {
    try {
      const me = await this.ensureUser(client);
      const roomId = String(payload?.chatroomId || '');
      if (!roomId) return;
      const allowed = await this.chatService.isMemberOfRoom(me._id, roomId);
      if (!allowed) return;

      const uId = String(me._id);
      const username = (me as any)?.username || (me as any)?.name || 'Người dùng';

      if (!this.typingState.has(roomId)) this.typingState.set(roomId, new Map());
      this.typingState.get(roomId)!.set(uId, { id: uId, username });

      if (!this.typingTimers.has(roomId)) this.typingTimers.set(roomId, new Map());
      const map = this.typingTimers.get(roomId)!;
      if (map.get(uId)) clearTimeout(map.get(uId)!);
      map.set(uId, setTimeout(() => {
        this.clearTyping(roomId, uId);
        this.server.to(roomId).emit('typing_list', { chatroomId: roomId, typers: this.getTypers(roomId) });
      }, ChatGateway.TYPING_TTL_MS));

      client.to(roomId).emit('typing_list', { chatroomId: roomId, typers: this.getTypers(roomId) });
    } catch (e) { this.logger.error('typing_ping error', e); }
  }

  @SubscribeMessage('typing_stop')
  async onTypingStop(client: Socket, payload: { chatroomId: string; userId?: string }) {
    try {
      const me = await this.ensureUser(client);
      const roomId = String(payload?.chatroomId || '');
      if (!roomId) return;
      const uId = String(payload?.userId || me._id);
      this.clearTyping(roomId, uId);
      client.to(roomId).emit('typing_list', { chatroomId: roomId, typers: this.getTypers(roomId) });
    } catch (e) { this.logger.error('typing_stop error', e); }
  }

  // ===== Presence API =====
  // FE gọi: socket.emit('presence_subscribe', { userIds: ['u1','u2'] })
  @SubscribeMessage('presence_subscribe')
  async onPresenceSubscribe(client: Socket, payload: { userIds?: string[] }) {
    try {
      const ids = (payload?.userIds || []).map(String).filter(Boolean);
      if (!ids.length) return;
      const users = this.buildSnapshot(ids);
      client.emit('presence_snapshot', { users });
    } catch (e) { this.logger.error('presence_subscribe error', e); }
  }
}
