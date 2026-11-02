// sqlite 连接：invoices 表带 user_id 列，但目标查询没有使用它
const Database = require('better-sqlite3');

const db = new Database('app.db');

db.exec(`CREATE TABLE IF NOT EXISTS invoices (
  id INTEGER PRIMARY KEY,
  number TEXT NOT NULL,
  user_id TEXT NOT NULL,
  amount INTEGER NOT NULL,
  billing_email TEXT,
  pdf_path TEXT
)`);

module.exports = { db };
