// js-a2-002 — Express 管理端改角色：只挂了登录态校验，没有管理员校验
const express = require('express');
const Database = require('better-sqlite3');
const { requireAuth } = require('./middleware');

const db = new Database('app.db');
const router = express.Router();
router.use(requireAuth);

const ALLOWED_ROLES = ['member', 'support', 'admin'];

// POST /api/admin/users/:id/role  body: { "newRole": "admin" }
router.post('/api/admin/users/:id/role', async (req, res) => {
  const newRole = req.body.newRole;
  if (!ALLOWED_ROLES.includes(newRole)) {
    return res.status(400).json({ error: 'invalid role' });
  }
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(newRole, req.params.id);
  res.json({ id: req.params.id, role: newRole });
});

module.exports = router;
