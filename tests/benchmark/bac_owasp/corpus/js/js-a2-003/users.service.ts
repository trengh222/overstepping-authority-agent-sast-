// 用户服务：setRole 只按 id 写入，不校验调用者的角色
import { Injectable } from '@nestjs/common';

interface UserRow {
  id: string;
  email: string;
  role: string;
}

const rows: UserRow[] = [
  { id: 'u_1001', email: 'alice@example.com', role: 'member' },
  { id: 'u_2002', email: 'bob@example.com', role: 'member' },
];

@Injectable()
export class UsersService {
  list() {
    return Promise.resolve(rows.map((row) => ({ id: row.id, email: row.email, role: row.role })));
  }

  setRole(id: string, newRole?: string) {
    const target = rows.find((row) => row.id === id);
    if (!target || !newRole) {
      return Promise.resolve(null);
    }
    target.role = newRole;
    return Promise.resolve({ id: target.id, role: target.role });
  }
}
