// js-a1-010 — NestJS 文件下载：service 层同时按属主与主键过滤
import {
  Controller,
  Get,
  NotFoundException,
  Param,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import type { Response } from 'express';
import { FilesService } from './files.service';

@UseGuards(AuthGuard('jwt'))
@Controller('api/files')
export class FilesController {
  constructor(private readonly files: FilesService) {}

  @Get(':id/download')
  async download(
    @Param('id') id: string,
    @Req() req: { user: { sub: string } },
    @Res() res: Response
  ) {
    const file = await this.files.findOwned(req.user.sub, id);
    if (!file) {
      throw new NotFoundException('file not found');
    }
    return res.download(file.path, file.name);
  }
}
