import sqlite3

from flask import Flask, jsonify, request
from flask_login import login_required

app = Flask(__name__)


@app.route("/api/admin/users/<int:user_id>/role", methods=["POST"])
@login_required
def change_role(user_id):
    payload = request.json or {}
    role = payload.get("role")
    if role not in ("user", "admin"):
        return jsonify({"error": "invalid role"}), 400
    conn = sqlite3.connect("app.db")
    try:
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"user_id": user_id, "role": role})
