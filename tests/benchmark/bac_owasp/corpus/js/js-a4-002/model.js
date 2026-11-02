// Mongoose 模型：notifications 集合以 userId 作为归属外键
const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
  userId: { type: String, index: true, required: true },
  title: String,
  body: String,
  read: { type: Boolean, default: false },
});

const NotificationModel = mongoose.model('Notification', notificationSchema);

module.exports = { NotificationModel };
