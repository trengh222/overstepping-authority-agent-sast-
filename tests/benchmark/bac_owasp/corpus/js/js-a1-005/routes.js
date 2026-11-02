// js-a1-005 — Express 批量文件元数据：ids 全部来自请求体
const express = require('express');
const { FileModel } = require('./model');

const router = express.Router();

// POST /api/files/batch  body: { "ids": ["f-01", "f-02"] }
router.post('/api/files/batch', async (req, res) => {
  const ids = req.body.ids;
  if (!Array.isArray(ids)) {
    return res.status(400).json({ error: 'ids must be an array' });
  }
  const files = await FileModel.find({ _id: { $in: ids } }, { name: 1, size: 1, path: 1 }).lean();
  res.json(files);
});

module.exports = router;
