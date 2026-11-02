// 鉴权 + 角色中间件：requireAuth 只校验登录态，requireAdmin 才校验管理员角色
function requireAuth(req, res, next) {
  const user = req.session && req.session.user;
  if (!user) {
    return res.status(401).json({ error: 'unauthenticated' });
  }
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'admin role required' });
  }
  next();
}

module.exports = { requireAuth, requireAdmin };
