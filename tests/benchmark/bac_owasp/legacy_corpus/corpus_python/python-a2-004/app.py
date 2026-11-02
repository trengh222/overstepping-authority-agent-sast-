import sqlite3

from flask import Flask, jsonify, request
from flask_login import login_required

app = Flask(__name__)


@app.route("/api/admin/settings", methods=["PUT"])
@login_required
def update_settings():
    payload = request.json or {}
    conn = sqlite3.connect("app.db")
    try:
        for key, value in payload.items():
            conn.execute(
                "UPDATE settings SET value = ? WHERE key = ?",
                (str(value), key),
            )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"updated": sorted(payload)})
