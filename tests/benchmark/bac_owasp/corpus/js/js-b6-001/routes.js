// js-b6-001 — Express 个人资料：整行实体直接 res.json，敏感列全部下发
const express = require('express');
const Database = require('better-sqlite3');
const { requireAuth } = require('./middleware');

const db = new Database('app.db');
const router = express.Router();
router.use(requireAuth);

// GET /api/me
router.get('/api/me', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) {
    return res.status(404).json({ error: 'user not found' });
  }
  // password_hash / ssn / mfa_secret 一并返回
  res.json(user);
});

module.exports = router;
