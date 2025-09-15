import {
  SubscribeMessage,
  WebSocketGateway,
  OnGatewayConnection,
  OnGatewayDisconnect,
  WebSocketServer,
  MessageBody,
  ConnectedSocket,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from '../auth/schemas/user.schema';

@WebSocketGateway({ namespace: 'webrtc', cors: { origin: '*' } })
export class WebRTCGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer() server: Server;
  private logger = new Logger('WebRTCGateway');

  constructor(
    private jwtService: JwtService,
    private config: ConfigService,
    @InjectModel(User.name) private userModel: Model<UserDocument>,
  ) {}

  async handleConnection(client: Socket) {
    try {
      const bearer = client.handshake.headers.authorization;
      const tokenFromHeader = bearer?.startsWith('Bearer ') ? bearer.slice(7) : bearer;
      const tokenFromAuth = (client.handshake as any)?.auth?.token;
      const tokenFromQuery = (client.handshake.query?.token as string) || undefined;
      const token = tokenFromHeader || tokenFromAuth || tokenFromQuery;
      if (!token) throw new Error('No token provided');

      const payload = this.jwtService.verify(token, {
        secret: this.config.get<string>('JWT_SECRET'),
      });
      const userId = (payload as any)?.sub || (payload as any)?.userId || (payload as any)?.id;

      const u = await this.userModel
        .findById(userId)
        .select('username avatar avatarUrl profile.avatarUrl')
        .lean();

      if (!u) throw new Error('User not found');

      const avatar =
        (u as any)?.avatarUrl ||
        (u as any)?.profile?.avatarUrl ||
        (u as any)?.avatar ||
        null;

      client.data.user = { _id: String(userId), username: u.username, avatar };
      this.logger.log(`Client connected: ${u.username} (${client.id})`);
    } catch (e: any) {
      this.logger.error(`Authentication failed: ${e?.message || e}`);
      client.disconnect(true);
    }
  }

  handleDisconnect(client: Socket) {
    const name = client.data?.user?.username || client.id;
    this.logger.log(`Client disconnected: ${name}`);
  }

  @SubscribeMessage('join-call')
  async handleJoinCall(@MessageBody() data: { roomId: string }, @ConnectedSocket() client: Socket) {
    const roomName = `call-${data.roomId}`;

    // sockets đang ở phòng (kèm user)
    const sockets = await this.server.in(roomName).fetchSockets();
    const existing = sockets
      .filter((s) => s.id !== client.id)
      .map((s) => ({ socketId: s.id, user: s.data.user }));

    client.join(roomName);

    client.emit('existing-participants', existing); // gửi cho người mới
    client.to(roomName).emit('user-joined', { socketId: client.id, user: client.data.user }); // báo cho người cũ

    this.logger.log(`${client.data.user.username} joined room ${data.roomId}`);
  }

  @SubscribeMessage('leave-call')
  handleLeaveCall(@MessageBody() data: { roomId: string }, @ConnectedSocket() client: Socket) {
    const roomName = `call-${data.roomId}`;
    client.to(roomName).emit('user-left', { socketId: client.id });
    client.leave(roomName);
    this.logger.log(`${client.data?.user?.username || client.id} left room ${data.roomId}`);
  }

  @SubscribeMessage('offer')
  handleOffer(@MessageBody() d: { targetSocketId: string; sdp: any }, @ConnectedSocket() c: Socket) {
    this.server.to(d.targetSocketId).emit('offer', { fromSocketId: c.id, sdp: d.sdp });
  }
  @SubscribeMessage('answer')
  handleAnswer(@MessageBody() d: { targetSocketId: string; sdp: any }, @ConnectedSocket() c: Socket) {
    this.server.to(d.targetSocketId).emit('answer', { fromSocketId: c.id, sdp: d.sdp });
  }
  @SubscribeMessage('ice-candidate')
  handleIce(@MessageBody() d: { targetSocketId: string; candidate: any }, @ConnectedSocket() c: Socket) {
    this.server.to(d.targetSocketId).emit('ice-candidate', { fromSocketId: c.id, candidate: d.candidate });
  }

  @SubscribeMessage('screen-share')
  handleScreen(@MessageBody() d: { roomId: string; on: boolean }, @ConnectedSocket() c: Socket) {
    const room = `call-${d.roomId}`;
    c.to(room).emit('screen-share', { socketId: c.id, on: d.on });
  }
}
