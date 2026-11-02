// js-a1-007 — Express 地址详情：查询条件同时绑定当前用户
const express = require('express');
const { requireAuth } = require('./middleware');

const router = express.Router();
router.use(requireAuth);

// 内存表：addresses 记录带 userId
const addresses = [
  { _id: 'a-01', userId: 'u_1001', line1: '长安街 1 号', city: '北京', zip: '100000' },
  { _id: 'a-02', userId: 'u_2002', line1: '南京路 8 号', city: '上海', zip: '200001' },
];

const Address = {
  async findOne(filter) {
    return addresses.find(
      (row) => row._id === filter._id && row.userId === filter.userId
    ) ?? null;
  },
};

// GET /api/addresses/:id
router.get('/api/addresses/:id', async (req, res) => {
  const address = await Address.findOne({ _id: req.params.id, userId: req.user.id });
  if (!address) {
    return res.status(404).json({ error: 'address not found' });
  }
  res.json(address);
});

module.exports = router;
