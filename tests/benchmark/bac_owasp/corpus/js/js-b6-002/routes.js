// js-b6-002 — Express 订单回执：归属校验通过后仍 JSON.stringify 整个实体
const express = require('express');
const { requireAuth } = require('./middleware');
const { Order } = require('./model');

const router = express.Router();
router.use(requireAuth);

// GET /api/orders/:id
router.get('/api/orders/:id', async (req, res) => {
  const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
  if (!order) {
    return res.status(404).json({ error: 'order not found' });
  }
  // 整实体序列化：internalCost / paymentIntentId 一并外泄
  res.type('application/json').send(JSON.stringify(order));
});

module.exports = router;
