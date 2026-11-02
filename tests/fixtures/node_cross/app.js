const express = require('express');
const app = express();

// 正样本：仅按 id 查询，无归属约束（跨过程进入 findById 方法体）
function findById(id) {
  return prisma.order.findUnique({ where: { id: id } });
}

// 负样本：带 userId 归属约束
function findOwnOrder(id, userId) {
  return prisma.order.findUnique({ where: { id: id, userId: userId } });
}

app.get('/api/order/:id', function (req, res) {
  const order = findById(req.params.id);
  res.json(order);
});

app.get('/api/order/mine/:id', function (req, res) {
  const order = findOwnOrder(req.params.id, req.user.id);
  res.json(order);
});
