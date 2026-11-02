"""A1 负例：SQL 带 user_id 归属过滤，取当前登录用户。"""
from flask import Flask, jsonify, session
import sqlite3

app = Flask(__name__)


@app.route("/api/documents/<int:document_id>", methods=["GET"])
def get_documents(document_id):
    uid = session.get("uid")
    conn = sqlite3.connect("app.db")
    row = conn.execute(
        "SELECT * FROM documents WHERE id = ? AND user_id = ?", (document_id, uid)
    ).fetchone()
    return jsonify(dict(row) if row else {})
