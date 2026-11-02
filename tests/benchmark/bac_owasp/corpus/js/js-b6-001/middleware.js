// 会话鉴权中间件：验签后把当前用户挂到 req.user
function requireAuth(req, res, next) {
  const user = req.session && req.session.user;
  if (!user) {
    return res.status(401).json({ error: 'unauthenticated' });
  }
  req.user = { id: user.id, role: user.role };
  next();
}

module.exports = { requireAuth };
