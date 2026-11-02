// js-a3-004 — 目标端点：账户列表按会话用户过滤
const express = require('express');
const Database = require('better-sqlite3');

const db = new Database('app.db');
const router = express.Router();

// GET /api/accounts
router.get('/accounts', (req, res) => {
  const rows = db
    .prepare('SELECT id, masked_number, balance FROM accounts WHERE user_id = ?')
    .all(req.user.id);
  res.json(rows);
});

module.exports = router;
