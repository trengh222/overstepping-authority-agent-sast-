// 内存模型：orders 每条记录都带归属字段 userId
const orders = [
  { id: '1001', userId: 'u_1001', status: 'paid', total: 1200, items: 3 },
  { id: '1002', userId: 'u_2002', status: 'shipped', total: 340, items: 1 },
  { id: '1003', userId: 'u_3003', status: 'refunded', total: 75, items: 2 },
];

module.exports = { orders };
