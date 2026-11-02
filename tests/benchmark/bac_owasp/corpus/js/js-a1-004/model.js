// Sequelize 模型：messages 表以 userId 作为归属外键
const { Sequelize, DataTypes } = require('sequelize');

const sequelize = new Sequelize(process.env.DATABASE_URL, { dialect: 'postgres' });

const Message = sequelize.define('Message', {
  userId: { type: DataTypes.STRING, allowNull: false, index: true },
  subject: DataTypes.STRING,
  body: DataTypes.TEXT,
  createdAt: DataTypes.DATE,
});

module.exports = { Message };
