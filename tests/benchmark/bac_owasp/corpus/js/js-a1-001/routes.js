// js-a1-001 — Express 订单详情：对象标识来自路径参数，未与当前用户绑定
const express = require('express');
const { orders } = require('./db');

const router = express.Router();

// GET /api/orders/:id
router.get('/api/orders/:id', async (req, res) => {
  const order = orders.find((item) => String(item.id) === req.params.id);
  if (!order) {
    return res.status(404).json({ error: 'order not found' });
  }
  res.json(order);
});

module.exports = router;
