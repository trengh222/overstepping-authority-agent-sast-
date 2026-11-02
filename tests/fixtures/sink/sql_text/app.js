const express = require('express');
const app = express();

// [A1] 原生 node-postgres：方法名 query 不在白名单、接收者 client 非 DAO，
// 仅靠「调用实参含原生 SQL 文本」识别为数据访问 sink（通用数据访问识别）
app.get('/api/order/:id', (req, res) => {
    const id = req.params.id;
    client.query('SELECT * FROM orders WHERE id = $1', [id], (err, rows) => {
        res.json(rows);
    });
});
