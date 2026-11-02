// js-b6-003 — NestJS 订单详情：controller 只返回白名单字段
import {
  Controller,
  Get,
  NotFoundException,
  Param,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { OrdersService } from './orders.service';
import { pick } from './serializer';

const PUBLIC_ORDER_FIELDS = ['id', 'status', 'total', 'createdAt'] as const;

@UseGuards(AuthGuard('jwt'))
@Controller('api/orders')
export class OrdersController {
  constructor(private readonly orders: OrdersService) {}

  @Get(':id')
  async findOne(@Param('id') id: string, @Req() req: { user: { sub: string } }) {
    const order = await this.orders.findOwned(req.user.sub, id);
    if (!order) {
      throw new NotFoundException('order not found');
    }
    return pick(order, PUBLIC_ORDER_FIELDS);
  }
}
