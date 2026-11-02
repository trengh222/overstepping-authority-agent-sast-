// 工单仓储：记录带 ownerId，供 controller 做归属判定
import { Injectable } from '@nestjs/common';

interface TicketRow {
  id: string;
  ownerId: string;
  subject: string;
  status: string;
}

const rows: TicketRow[] = [
  { id: 't-01', ownerId: 'u_1001', subject: '无法登录', status: 'open' },
  { id: 't-02', ownerId: 'u_2002', subject: '退款未到账', status: 'pending' },
];

@Injectable()
export class TicketsService {
  findById(id: string) {
    return Promise.resolve(rows.find((row) => row.id === id) ?? null);
  }
}
