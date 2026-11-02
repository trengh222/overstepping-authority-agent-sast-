// js-a2-001 — Express 管理端删除用户：同模块其它路由有角色校验，删除路由漏了
const express = require('express');
const Database = require('better-sqlite3');
const { requireAuth, requireAdmin } = require('./middleware');

const db = new Database('app.db');
const router = express.Router();
router.use(requireAuth);

// GET /api/admin/users —— 同模块的管理路由带了 requireAdmin
router.get('/api/admin/users', requireAdmin, async (req, res) => {
  res.json(db.prepare('SELECT id, email, role FROM users').all());
});

// DELETE /api/admin/users/:id —— 只校验了登录态
router.delete('/api/admin/users/:id', async (req, res) => {
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.status(204).end();
});

module.exports = router;
