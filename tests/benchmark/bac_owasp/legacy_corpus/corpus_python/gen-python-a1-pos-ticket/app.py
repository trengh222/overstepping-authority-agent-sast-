"""A1：Flask 路径参数直接按主键查库并返回。"""
from flask import Flask, jsonify
import sqlite3

app = Flask(__name__)


@app.route("/api/tickets/<int:ticket_id>", methods=["GET"])
def get_tickets(ticket_id):
    conn = sqlite3.connect("app.db")
    row = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    return jsonify(dict(row) if row else {})
