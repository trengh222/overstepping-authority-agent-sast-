// Mongoose 模型：orders 含内部成本、支付渠道密钥等不应外发的列
const mongoose = require('mongoose');

const orderSchema = new mongoose.Schema({
  userId: { type: String, index: true, required: true },
  status: String,
  total: Number,
  internalCost: Number,
  paymentIntentId: String,
  ownerNote: String,
});

const Order = mongoose.model('Order', orderSchema);

module.exports = { Order };
