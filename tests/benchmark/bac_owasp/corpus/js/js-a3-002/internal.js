// js-a3-002 — 目标端点：/internal/** 匿名可读全量会话与在线指标
const express = require('express');

const router = express.Router();

// 会话表由登录模块写入（此处只需读取，展示越权后果）
const sessions = new Map([
  ['sess_01', { userId: 'u_1001', ip: '10.0.0.8', role: 'admin' }],
  ['sess_02', { userId: 'u_2002', ip: '10.0.0.9', role: 'member' }],
]);

// GET /internal/metrics/sessions
router.get('/internal/metrics/sessions', (req, res) => {
  const snapshot = [...sessions.entries()].map(([id, item]) => ({
    sessionId: id,
    userId: item.userId,
    ip: item.ip,
    role: item.role,
  }));
  res.json({ count: snapshot.length, sessions: snapshot });
});

module.exports = router;
