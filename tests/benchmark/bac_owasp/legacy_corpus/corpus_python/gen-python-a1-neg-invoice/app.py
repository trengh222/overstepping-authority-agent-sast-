"""A1 负例：SQL 带 user_id 归属过滤，取当前登录用户。"""
from flask import Flask, jsonify, session
import sqlite3

app = Flask(__name__)


@app.route("/api/invoices/<int:invoice_id>", methods=["GET"])
def get_invoices(invoice_id):
    uid = session.get("uid")
    conn = sqlite3.connect("app.db")
    row = conn.execute(
        "SELECT * FROM invoices WHERE id = ? AND user_id = ?", (invoice_id, uid)
    ).fetchone()
    return jsonify(dict(row) if row else {})
