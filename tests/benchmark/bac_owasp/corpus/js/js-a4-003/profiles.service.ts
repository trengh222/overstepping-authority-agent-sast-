// 资料服务：写入时以令牌里的 userId 为主键，不接受外部指定的用户
import { Injectable } from '@nestjs/common';

const contacts = new Map<string, { email: string }>([
  ['u_1001', { email: 'alice@example.com' }],
  ['u_2002', { email: 'bob@example.com' }],
]);

@Injectable()
export class ProfilesService {
  updateOwnContact(userId: string, email: string) {
    contacts.set(userId, { email });
    return { userId, email };
  }
}
