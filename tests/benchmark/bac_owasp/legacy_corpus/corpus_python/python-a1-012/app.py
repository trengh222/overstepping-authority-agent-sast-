import sqlite3

from flask import Flask, abort, jsonify
from flask_login import current_user, login_required

app = Flask(__name__)


@app.route("/api/orders/<int:order_id>/summary", methods=["GET"])
@login_required
def order_summary(order_id):
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT id, status, total FROM orders WHERE id = ? AND user_id = ?",
            (order_id, current_user.id),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        abort(404)
    return jsonify(dict(row))
