// A1：Express 直接按 :id 查库返回，无归属校验。
const express = require("express");
const db = require("../db");

const router = express.Router();

router.get("/api/documents/:id", async (req, res) => {
  const row = await db.query("SELECT * FROM documents WHERE id = ?", [req.params.id]);
  res.json(row);
});

module.exports = router;
