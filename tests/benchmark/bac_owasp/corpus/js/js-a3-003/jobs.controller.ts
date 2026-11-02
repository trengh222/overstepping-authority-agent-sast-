// js-a3-003 — NestJS 内部作业控制器：没有 AuthGuard，可以匿名读取
import { Controller, Get } from '@nestjs/common';

interface DeadLetter {
  id: string;
  queue: string;
  payload: Record<string, unknown>;
}

const deadLetters: DeadLetter[] = [
  { id: 'dl-1', queue: 'billing.retry', payload: { userId: 'u_1001', amount: 1200 } },
  { id: 'dl-2', queue: 'mail.send', payload: { to: 'ops@example.com' } },
];

@Controller('internal/jobs')
export class JobsController {
  // GET /internal/jobs/dlq
  @Get('dlq')
  list() {
    return { total: deadLetters.length, items: deadLetters };
  }
}
