// js-a1-004 — Express 消息列表：归属用户完全由查询参数决定
const express = require('express');
const { Message } = require('./model');

const router = express.Router();

// GET /api/messages?userId=u_2002
router.get('/api/messages', async (req, res) => {
  const messages = await Message.findAll({
    where: { userId: req.query.userId },
    order: [['createdAt', 'DESC']],
    limit: 50,
  });
  res.json(messages);
});

module.exports = router;
