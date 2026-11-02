// js-a3-001 — Express 报表导出：整个应用没有挂任何鉴权中间件
const express = require('express');
const reportRoutes = require('./routes');

const app = express();
app.use(express.json());

// 注意：这里没有 app.use(requireAuth) 之类的全局鉴权
app.use('/api', reportRoutes);

app.listen(3000);

module.exports = app;
