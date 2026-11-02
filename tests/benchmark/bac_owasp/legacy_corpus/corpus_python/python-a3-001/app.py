import sqlite3

from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/internal/ops/reindex", methods=["POST"])
def reindex():
    conn = sqlite3.connect("app.db")
    try:
        conn.execute("UPDATE search_index SET stale = 1")
        conn.commit()
    finally:
        conn.close()
    return jsonify({"status": "queued"})
