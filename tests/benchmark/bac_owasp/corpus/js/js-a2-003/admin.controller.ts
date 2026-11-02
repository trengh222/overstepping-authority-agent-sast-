// js-a2-003 — NestJS 管理端改角色：只有 AuthGuard，没有角色守卫
import { Body, Controller, Get, Param, Post, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Roles, RolesGuard } from './roles.guard';
import { UsersService } from './users.service';

@Controller('api/admin')
export class AdminController {
  constructor(private readonly users: UsersService) {}

  // 同模块的管理路由带了角色守卫
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles('admin')
  @Get('users')
  list() {
    return this.users.list();
  }

  // 目标端点：只要求登录，任何登录用户都能改任意用户角色
  @UseGuards(AuthGuard('jwt'))
  @Post('users/:id/role')
  setRole(@Param('id') id: string, @Body() body: { newRole?: string }) {
    return this.users.setRole(id, body.newRole);
  }
}
