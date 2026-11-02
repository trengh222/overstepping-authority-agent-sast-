const express = require('express');
const app = express();

// [A1] 自研 DAO 基类：方法名 fetch 不在白名单，
// 仅靠「接收者名以 Repo 结尾」识别为数据访问 sink（通用数据访问识别）
app.get('/api/order/:id', (req, res) => {
    const id = req.params.id;
    const order = orderRepo.fetch(id);
    res.json(order);
});
