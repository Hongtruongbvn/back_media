// api/src/chat/typing.gateway.ts
import {
  MessageBody, ConnectedSocket, OnGatewayConnection, OnGatewayDisconnect,
  SubscribeMessage, WebSocketGateway, WebSocketServer
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';

type TypingUser = { id: string; username: string };

const TYPING_TTL_MS = 3500; // hết hạn nếu không ping nữa

@WebSocketGateway({
  cors: { origin: '*', credentials: true },
  namespace: '/chat',               // trùng namespace FE đang dùng nếu có
})
export class TypingGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer() io: Server;

  // roomId -> (userId -> timer)
  private timers = new Map<string, Map<string, NodeJS.Timeout>>();
  // roomId -> (userId -> user info)
  private state  = new Map<string, Map<string, TypingUser>>();

  handleConnection(socket: Socket) {
    // optional: đọc user từ token nếu bạn có middleware auth cho socket
    // socket.data.user = { id, username }
  }

  handleDisconnect(socket: Socket) {
    // khi disconnect, xoá user khỏi tất cả room họ đã join
    const rooms = Array.from(socket.rooms).filter(r => r !== socket.id);
    rooms.forEach(roomId => {
      const user: TypingUser | undefined = socket.data?.user;
      if (!user) return;
      this.clearUser(roomId, user.id);
      socket.to(roomId).emit('typing:list', { roomId, typers: this.getTypers(roomId) });
    });
  }

  /** Client nên gọi trước đó: socket.emit('room:join', { roomId }) để join room */
  @SubscribeMessage('room:join')
  onJoin(@ConnectedSocket() socket: Socket, @MessageBody() body: any) {
    const { roomId, user } = body || {};
    if (!roomId) return;
    if (user) socket.data.user = user; // {id, username}
    socket.join(String(roomId));
  }

  /** Ping khi gõ phím (mỗi ~1.5–2s): server gia hạn TTL và broadcast danh sách */
  @SubscribeMessage('typing:ping')
  onTypingPing(@ConnectedSocket() socket: Socket, @MessageBody() body: any) {
    const { roomId, user } = body || {};
    if (!roomId || !user?.id) return;

    const rId = String(roomId);
    // lưu user
    if (!this.state.has(rId)) this.state.set(rId, new Map());
    this.state.get(rId)!.set(String(user.id), { id: String(user.id), username: user.username });

    // reset timer TTL
    if (!this.timers.has(rId)) this.timers.set(rId, new Map());
    const map = this.timers.get(rId)!;
    const uId = String(user.id);
    if (map.get(uId)) clearTimeout(map.get(uId)!);
    map.set(uId, setTimeout(() => {
      this.clearUser(rId, uId);
      this.io.to(rId).emit('typing:list', { roomId: rId, typers: this.getTypers(rId) });
    }, TYPING_TTL_MS));

    // phát cho người khác trong phòng (không gửi lại cho chính người gõ)
    socket.to(rId).emit('typing:list', { roomId: rId, typers: this.getTypers(rId, /*excludeId*/ undefined) });
  }

  /** (tuỳ chọn) gọi khi blur/submit để dừng sớm */
  @SubscribeMessage('typing:stop')
  onTypingStop(@ConnectedSocket() socket: Socket, @MessageBody() body: any) {
    const { roomId, userId } = body || {};
    if (!roomId || !userId) return;
    const rId = String(roomId), uId = String(userId);
    this.clearUser(rId, uId);
    socket.to(rId).emit('typing:list', { roomId: rId, typers: this.getTypers(rId) });
  }

  private clearUser(roomId: string, userId: string) {
    const t = this.timers.get(roomId)?.get(userId);
    if (t) clearTimeout(t);
    this.timers.get(roomId)?.delete(userId);
    this.state.get(roomId)?.delete(userId);
  }

  private getTypers(roomId: string, excludeId?: string): TypingUser[] {
    const m = this.state.get(roomId);
    if (!m) return [];
    const arr = Array.from(m.values());
    return excludeId ? arr.filter(x => x.id !== excludeId) : arr;
  }
}
