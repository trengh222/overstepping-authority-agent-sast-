// 文件仓储：findOwned 把 ownerId 作为查询条件的一部分
import { Injectable } from '@nestjs/common';

interface FileRow {
  _id: string;
  ownerId: string;
  name: string;
  path: string;
}

const rows: FileRow[] = [
  { _id: 'f-01', ownerId: 'u_1001', name: 'invoice.pdf', path: '/srv/files/f-01.pdf' },
  { _id: 'f-02', ownerId: 'u_2002', name: 'contract.pdf', path: '/srv/files/f-02.pdf' },
];

@Injectable()
export class FilesService {
  findOwned(ownerId: string, id: string) {
    return Promise.resolve(
      rows.find((row) => row._id === id && row.ownerId === ownerId) ?? null
    );
  }
}
