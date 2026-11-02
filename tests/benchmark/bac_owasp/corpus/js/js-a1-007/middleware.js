// 会话鉴权中间件：校验签名 cookie 后把用户挂到 req.user
function requireAuth(req, res, next) {
  const session = req.signedCookies && req.signedCookies.session;
  if (!session || !session.userId) {
    return res.status(401).json({ error: 'unauthenticated' });
  }
  req.user = { id: session.userId, role: session.role };
  next();
}

module.exports = { requireAuth };
