"""A1 负例：SQL 带 user_id 归属过滤，取当前登录用户。"""
from flask import Flask, jsonify, session
import sqlite3

app = Flask(__name__)


@app.route("/api/messages/<int:message_id>", methods=["GET"])
def get_messages(message_id):
    uid = session.get("uid")
    conn = sqlite3.connect("app.db")
    row = conn.execute(
        "SELECT * FROM messages WHERE id = ? AND user_id = ?", (message_id, uid)
    ).fetchone()
    return jsonify(dict(row) if row else {})
