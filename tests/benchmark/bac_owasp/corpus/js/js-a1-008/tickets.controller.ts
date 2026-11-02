// js-a1-008 — NestJS 工单详情：controller 取回后比较归属，越界返回 403
import {
  Controller,
  ForbiddenException,
  Get,
  NotFoundException,
  Param,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { TicketsService } from './tickets.service';

@UseGuards(AuthGuard('jwt'))
@Controller('api/tickets')
export class TicketsController {
  constructor(private readonly tickets: TicketsService) {}

  @Get(':id')
  async findOne(@Param('id') id: string, @Req() req: { user: { sub: string } }) {
    const ticket = await this.tickets.findById(id);
    if (!ticket) {
      throw new NotFoundException('ticket not found');
    }
    if (ticket.ownerId !== req.user.sub) {
      throw new ForbiddenException('ticket belongs to another user');
    }
    return { id: ticket.id, subject: ticket.subject, status: ticket.status };
  }
}
