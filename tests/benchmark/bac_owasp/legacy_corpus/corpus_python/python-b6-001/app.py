import sqlite3

from flask import Flask, abort, jsonify
from flask_login import current_user, login_required

app = Flask(__name__)


@app.route("/api/users/<int:user_id>", methods=["GET"])
@login_required
def user_profile(user_id):
    if user_id != current_user.id:
        abort(403)
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        abort(404)
    return jsonify(dict(row))
