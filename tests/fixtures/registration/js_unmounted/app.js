const express = require('express');

// 注册可达正样本：router 定义路由但从未 app.use(router) → 未被挂载，端点不可达
const router = express.Router();

function findById(id) {
  return prisma.order.findUnique({ where: { id: id } });
}

router.get('/api/order/:id', function (req, res) {
  const order = findById(req.params.id);
  res.json(order);
});
