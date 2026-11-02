const express = require('express');
const { PrismaClient } = require('@prisma/client');

const app = express();
const prisma = new PrismaClient();

// 别名场景：uid = req.params.id 后再查询（单跳别名，此前会漏）
app.get('/api/order/:id', async (req, res) => {
    const uid = req.params.id;
    const order = await prisma.order.findUnique({ where: { id: uid } });
    res.json(order);
});