// 鉴权中间件：仅校验会话登录态，不涉及角色
function requireAuth(req, res, next) {
  const user = req.session && req.session.user;
  if (!user) {
    return res.status(401).json({ error: 'unauthenticated' });
  }
  req.user = user;
  next();
}

module.exports = { requireAuth };
