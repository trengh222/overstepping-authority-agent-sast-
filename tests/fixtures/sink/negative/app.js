const express = require('express');
const app = express();

// 负样本：方法名 formatName 不在白名单、接收者 orderService 不像 DAO、实参无 SQL 文本
// → 不应产出数据访问候选
app.get('/api/order/:id', (req, res) => {
    const id = req.params.id;
    const name = orderService.formatName(id);
    res.json(name);
});
