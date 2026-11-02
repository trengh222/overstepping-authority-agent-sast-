// js-a4-003 — NestJS 联系方式更新：身份与角色都来自验签令牌，请求体的 role 被拒绝
import {
  BadRequestException,
  Body,
  Controller,
  ForbiddenException,
  Patch,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ProfilesService } from './profiles.service';

interface AuthedRequest {
  user: { sub: string; role: string };
}

@UseGuards(AuthGuard('jwt'))
@Controller('api/profile')
export class ProfileController {
  constructor(private readonly profiles: ProfilesService) {}

  // PATCH /api/profile/contact
  @Patch('contact')
  update(@Req() req: AuthedRequest, @Body() body: { email?: string; role?: string }) {
    // 角色只认令牌声明：请求体里传 role 一律拒绝
    if (body.role !== undefined && body.role !== req.user.role) {
      throw new ForbiddenException('role is derived from the access token');
    }
    if (!body.email) {
      throw new BadRequestException('email is required');
    }
    return this.profiles.updateOwnContact(req.user.sub, body.email);
  }
}
