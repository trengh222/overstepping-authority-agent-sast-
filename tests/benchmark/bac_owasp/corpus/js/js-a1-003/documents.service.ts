// 内存仓储：documents 记录带 ownerId，service 查询时没有使用它
import { Injectable } from '@nestjs/common';

interface DocumentRow {
  _id: string;
  ownerId: string;
  title: string;
  body: string;
}

const rows: DocumentRow[] = [
  { _id: 'd-01', ownerId: 'u_1001', title: '季度报表', body: '营收 1200 万' },
  { _id: 'd-02', ownerId: 'u_2002', title: '离职证明', body: '员工 u_2002' },
];

@Injectable()
export class DocumentsService {
  findOne(id: string) {
    return Promise.resolve(rows.find((row) => row._id === id) ?? null);
  }
}
