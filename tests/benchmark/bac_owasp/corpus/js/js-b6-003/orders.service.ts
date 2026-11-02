// 订单仓储：findOwned 同时匹配主键与属主
import { Injectable } from '@nestjs/common';

interface OrderRow {
  id: string;
  userId: string;
  status: string;
  total: number;
  createdAt: string;
  internalCost: number;
  paymentIntentId: string;
}

const rows: OrderRow[] = [
  {
    id: 'o-01',
    userId: 'u_1001',
    status: 'paid',
    total: 1200,
    createdAt: '2024-05-01T08:00:00Z',
    internalCost: 640,
    paymentIntentId: 'pi_9f2c',
  },
  {
    id: 'o-02',
    userId: 'u_2002',
    status: 'shipped',
    total: 340,
    createdAt: '2024-05-03T11:20:00Z',
    internalCost: 190,
    paymentIntentId: 'pi_7a1b',
  },
];

@Injectable()
export class OrdersService {
  findOwned(userId: string, id: string) {
    return Promise.resolve(
      rows.find((row) => row.id === id && row.userId === userId) ?? null
    );
  }
}
