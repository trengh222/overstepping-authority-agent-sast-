// js-a2-004 — Express 管理端退款：路由链上同时带了登录与角色中间件
const express = require('express');
const Database = require('better-sqlite3');
const { requireAuth, requireRole } = require('./middleware');

const db = new Database('app.db');
const router = express.Router();
router.use(requireAuth);

// POST /api/admin/refunds
router.post('/api/admin/refunds', requireRole('admin'), async (req, res) => {
  const { orderId, amount } = req.body;
  if (!orderId || !Number.isInteger(amount) || amount <= 0) {
    return res.status(400).json({ error: 'orderId and amount are required' });
  }
  const info = db
    .prepare('INSERT INTO refunds (order_id, amount, created_by) VALUES (?, ?, ?)')
    .run(orderId, amount, req.user.id);
  res.status(201).json({ id: info.lastInsertRowid });
});

module.exports = router;
