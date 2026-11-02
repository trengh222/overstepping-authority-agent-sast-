// js-a1-009 — Express 订单列表：SQL 条件绑定当前用户
const express = require('express');
const Database = require('better-sqlite3');
const { requireAuth } = require('./middleware');

const db = new Database('app.db');
const router = express.Router();
router.use(requireAuth);

// GET /api/orders
router.get('/api/orders', async (req, res) => {
  const rows = db
    .prepare(
      'SELECT id, status, total, created_at FROM orders WHERE user_id = ? ORDER BY created_at DESC'
    )
    .all(req.user.id);
  res.json(rows);
});

module.exports = router;
