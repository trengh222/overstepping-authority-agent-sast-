"""A1：Flask 路径参数直接按主键查库并返回。"""
from flask import Flask, jsonify
import sqlite3

app = Flask(__name__)


@app.route("/api/invoices/<int:invoice_id>", methods=["GET"])
def get_invoices(invoice_id):
    conn = sqlite3.connect("app.db")
    row = conn.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    return jsonify(dict(row) if row else {})
