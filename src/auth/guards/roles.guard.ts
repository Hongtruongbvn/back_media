import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { GlobalRole } from '../schemas/user.schema';
import { ROLES_KEY } from '../decorators/roles.decorator'; // Import ROLES_KEY

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<GlobalRole[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!requiredRoles) {
      return true; // Nếu không yêu cầu vai trò, cho qua
    }
    const { user } = context.switchToHttp().getRequest();
    // Kiểm tra xem vai trò của người dùng có nằm trong danh sách vai trò được yêu cầu không
    return requiredRoles.some((role) => user.globalRole === role);
  }
}