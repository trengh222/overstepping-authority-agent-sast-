// A1：Express 直接按 :id 查库返回，无归属校验。
const express = require("express");
const db = require("../db");

const router = express.Router();

router.get("/api/invoices/:id", async (req, res) => {
  const row = await db.query("SELECT * FROM invoices WHERE id = ?", [req.params.id]);
  res.json(row);
});

module.exports = router;
