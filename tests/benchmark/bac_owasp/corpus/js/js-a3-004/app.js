// js-a3-004 — Express 应用：全局挂载 requireAuth，业务路由一律先验签
const express = require('express');
const accountRoutes = require('./routes');

const app = express();
app.use(express.json());

// 全局鉴权：所有后续路由都必须先通过会话验签
app.use(requireAuth);

app.use('/api', accountRoutes);

app.listen(3000);

module.exports = app;

function requireAuth(req, res, next) {
  const crypto = require('crypto');
  const raw = req.signedCookies && req.signedCookies.sid;
  if (!raw) {
    return res.status(401).json({ error: 'unauthenticated' });
  }
  const [payload, sig] = String(raw).split('.');
  const expected = crypto
    .createHmac('sha256', process.env.SESSION_SECRET || 'dev-secret')
    .update(payload || '')
    .digest('base64url');
  if (!sig || sig !== expected) {
    return res.status(401).json({ error: 'invalid session' });
  }
  req.user = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  next();
}
