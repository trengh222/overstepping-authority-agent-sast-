// js-a4-001 — Express 账单查询：身份取自客户端可伪造的 X-User-Id 请求头
const express = require('express');
const Database = require('better-sqlite3');

const db = new Database('app.db');
const router = express.Router();

// GET /api/billing/statements
router.get('/api/billing/statements', async (req, res) => {
  const userId = req.headers['x-user-id'];
  if (!userId) {
    return res.status(401).json({ error: 'missing X-User-Id' });
  }
  const rows = db
    .prepare('SELECT id, period, amount_due, card_last4 FROM statements WHERE user_id = ?')
    .all(userId);
  res.json(rows);
});

module.exports = router;
