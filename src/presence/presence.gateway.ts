import { WebSocketGateway, OnGatewayConnection, OnGatewayDisconnect, WebSocketServer } from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { PresenceService } from './presence.service';
import { Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@WebSocketGateway({ cors: { origin: '*' }, namespace: 'presence' })
export class PresenceGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer() server: Server;
  private logger = new Logger(PresenceGateway.name);

  constructor(
    private presenceService: PresenceService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async handleConnection(client: Socket) {
    try {
      const token = client.handshake.headers.authorization?.split(' ')[1];
      if (!token) throw new Error('No token');
      const payload = this.jwtService.verify(token, { secret: this.configService.get('JWT_SECRET') });
      const userId = payload.sub;

      this.presenceService.addUser(userId, client.id);
      client.data.userId = userId;
      this.server.emit('statusUpdate', { userId, status: 'ONLINE' });
      this.logger.log(`User ${userId} connected.`);
    } catch (e) {
      client.disconnect();
    }
  }

  handleDisconnect(client: Socket) {
    const userId = this.presenceService.removeUserBySocketId(client.id);
    if (userId) {
      this.server.emit('statusUpdate', { userId, status: 'OFFLINE' });
      this.logger.log(`User ${userId} disconnected.`);
    }
  }
}