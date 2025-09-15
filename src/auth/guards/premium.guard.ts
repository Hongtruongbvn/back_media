import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Observable } from 'rxjs';
import { UserDocument, AccountType } from '../schemas/user.schema';

@Injectable()
export class PremiumGuard implements CanActivate {
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request = context.switchToHttp().getRequest();
    const user = request.user as UserDocument;

    // SỬA LỖI & HOÀN THIỆN: Kiểm tra xem người dùng có tồn tại và có phải là PREMIUM không
    return user && user.accountType === AccountType.PREMIUM;
  }
}
