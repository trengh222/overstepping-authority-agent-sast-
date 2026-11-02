// js-a1-003 — NestJS 文档详情：@Param('id') 原样传给 service
import { Controller, Get, Param } from '@nestjs/common';
import { DocumentsService } from './documents.service';

@Controller('api/documents')
export class DocumentsController {
  constructor(private readonly documents: DocumentsService) {}

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.documents.findOne(id);
  }
}
