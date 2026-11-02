// js-a3-002 — 内部运维路由被直接挂到对公网开放的 app 上
const express = require('express');
const internal = require('./internal');

const app = express();
app.use(express.json());

// 注意：没有 requireInternalToken / IP 白名单之类的校验
app.use(internal);

app.listen(8080);

module.exports = app;
