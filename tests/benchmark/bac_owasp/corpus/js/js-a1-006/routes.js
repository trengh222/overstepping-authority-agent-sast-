// js-a1-006 — Express 收据下载：路径参数决定下载哪一笔支付
const express = require('express');
const { Payment } = require('./service');

const router = express.Router();

// GET /api/payments/:id/receipt
router.get('/api/payments/:id/receipt', async (req, res) => {
  const receipt = await Payment.getReceipt(req.params.id);
  if (!receipt) {
    return res.status(404).json({ error: 'receipt not found' });
  }
  res.download(receipt.filePath, `receipt-${receipt.paymentId}.pdf`);
});

module.exports = router;
