// js-a3-001 — 目标端点：匿名即可导出全部用户的报税记录
const express = require('express');
const Database = require('better-sqlite3');

const db = new Database('app.db');
const router = express.Router();

// GET /api/reports/export
router.get('/reports/export', async (req, res) => {
  const rows = db
    .prepare('SELECT user_id, full_name, tax_id, salary FROM tax_records LIMIT 5000')
    .all();
  res.setHeader('Content-Disposition', 'attachment; filename="tax_records.json"');
  res.json(rows);
});

module.exports = router;
