const express = require('express');

// 注册可达负样本：router 已 app.use 挂载 → 正常注册，不应提示不可达
const app = express();
const router = express.Router();

function findById(id) {
  return prisma.order.findUnique({ where: { id: id } });
}

router.get('/api/order/:id', function (req, res) {
  const order = findById(req.params.id);
  res.json(order);
});

app.use('/api', router);
