"""A1：Flask 路径参数直接按主键查库并返回。"""
from flask import Flask, jsonify
import sqlite3

app = Flask(__name__)


@app.route("/api/documents/<int:document_id>", methods=["GET"])
def get_documents(document_id):
    conn = sqlite3.connect("app.db")
    row = conn.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
    return jsonify(dict(row) if row else {})
