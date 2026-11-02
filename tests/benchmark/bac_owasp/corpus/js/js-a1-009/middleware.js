// 会话鉴权中间件：验签通过后把当前用户挂到 req.user
const crypto = require('crypto');

function verifySession(raw) {
  const [payload, sig] = String(raw).split('.');
  if (!payload || !sig) {
    return null;
  }
  const expected = crypto
    .createHmac('sha256', process.env.SESSION_SECRET || 'dev-secret')
    .update(payload)
    .digest('base64url');
  if (sig.length !== expected.length) {
    return null;
  }
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
    return null;
  }
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
}

function requireAuth(req, res, next) {
  const session = req.signedCookies && req.signedCookies.sid;
  const payload = session ? verifySession(session) : null;
  if (!payload) {
    return res.status(401).json({ error: 'unauthenticated' });
  }
  req.user = { id: payload.sub, role: payload.role };
  next();
}

module.exports = { requireAuth };
