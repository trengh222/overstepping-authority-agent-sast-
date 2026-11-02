// A1 负例：SQL 同时带 user_id，取会话里的当前用户。
const express = require("express");
const db = require("../db");

const router = express.Router();

router.get("/api/messages/:id", async (req, res) => {
  const uid = req.session.userId;
  const row = await db.query(
    "SELECT * FROM messages WHERE id = ? AND user_id = ?", [req.params.id, uid]
  );
  res.json(row);
});

module.exports = router;
