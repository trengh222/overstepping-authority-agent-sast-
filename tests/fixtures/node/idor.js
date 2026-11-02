const express = require('express');
const orderService = require('./orderService');

const app = express();

// [A1] Path 参数直查，无归属约束
app.get('/api/order/:id', (req, res) => {
    const order = orderService.findById(req.params.id);
    res.json(order);
});