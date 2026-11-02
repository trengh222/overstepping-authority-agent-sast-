// 支付服务：getReceipt 只按支付单号取收据，调用方身份不参与过滤
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const Payment = {
  async getReceipt(paymentId) {
    const { rows } = await pool.query(
      'SELECT payment_id, user_id, file_path FROM receipts WHERE payment_id = $1',
      [paymentId]
    );
    if (rows.length === 0) {
      return null;
    }
    return { paymentId: rows[0].payment_id, filePath: rows[0].file_path };
  },
};

module.exports = { Payment };
