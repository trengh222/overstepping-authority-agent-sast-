import sqlite3

from flask import Flask, abort, jsonify
from flask_login import current_user, login_required

app = Flask(__name__)


@app.route("/api/reviews/<int:review_id>", methods=["GET"])
@login_required
def get_review(review_id):
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT id, user_id, rating, comment FROM reviews WHERE id = ?",
            (review_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        abort(404)
    if row["user_id"] != current_user.id:
        abort(403)
    return jsonify(dict(row))
