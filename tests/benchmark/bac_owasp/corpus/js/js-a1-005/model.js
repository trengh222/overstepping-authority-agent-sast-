// Mongoose 模型：files 集合带 ownerId，批量查询没有使用它
const mongoose = require('mongoose');

const fileSchema = new mongoose.Schema({
  ownerId: { type: String, index: true, required: true },
  name: String,
  size: Number,
  path: String,
});

const FileModel = mongoose.model('File', fileSchema);

module.exports = { FileModel };
