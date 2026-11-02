// js-a1-002 — Express 发票详情：对象标识来自查询参数，SQL 未带归属条件
const express = require('express');
const { db } = require('./db');

const router = express.Router();

// GET /api/invoices?invoiceId=INV-2024-0001
router.get('/api/invoices', async (req, res) => {
  const invoice = db
    .prepare('SELECT id, number, amount, billing_email, pdf_path FROM invoices WHERE number = ?')
    .get(req.query.invoiceId);
  if (!invoice) {
    return res.status(404).json({ error: 'invoice not found' });
  }
  res.json(invoice);
});

module.exports = router;
