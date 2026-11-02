"""A1：Flask 路径参数直接按主键查库并返回。"""
from flask import Flask, jsonify
import sqlite3

app = Flask(__name__)


@app.route("/api/messages/<int:message_id>", methods=["GET"])
def get_messages(message_id):
    conn = sqlite3.connect("app.db")
    row = conn.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
    return jsonify(dict(row) if row else {})
