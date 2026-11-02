// 内部作业模块：providers 里没有 APP_GUARD，也没有挂任何守卫
import { Module } from '@nestjs/common';
import { JobsController } from './jobs.controller';

@Module({
  controllers: [JobsController],
  providers: [],
})
export class JobsModule {}
