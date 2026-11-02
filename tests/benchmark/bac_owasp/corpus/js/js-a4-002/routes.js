// js-a4-002 — Express 通知列表：身份取自未签名的 uid cookie
const express = require('express');
const cookieParser = require('cookie-parser');
const { NotificationModel } = require('./model');

const router = express.Router();
router.use(cookieParser());

// GET /api/notifications
router.get('/api/notifications', async (req, res) => {
  const uid = req.cookies.uid;
  if (!uid) {
    return res.status(401).json({ error: 'no uid cookie' });
  }
  const list = await NotificationModel.find({ userId: uid }).limit(100).lean();
  res.json(list);
});

module.exports = router;
