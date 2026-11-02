// 鉴权 + 角色中间件：requireRole 校验会话用户是否具备指定角色
function requireAuth(req, res, next) {
  const user = req.session && req.session.user;
  if (!user) {
    return res.status(401).json({ error: 'unauthenticated' });
  }
  req.user = user;
  next();
}

function requireRole(role) {
  return function roleGuard(req, res, next) {
    if (!req.user || req.user.role !== role) {
      return res.status(403).json({ error: `${role} role required` });
    }
    next();
  };
}

module.exports = { requireAuth, requireRole };
