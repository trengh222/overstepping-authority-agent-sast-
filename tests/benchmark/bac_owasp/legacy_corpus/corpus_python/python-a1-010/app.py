import sqlite3

from flask import Flask, abort, jsonify
from flask_login import current_user, login_required

app = Flask(__name__)


@app.route("/api/payments/<int:payment_id>", methods=["DELETE"])
@login_required
def delete_payment(payment_id):
    conn = sqlite3.connect("app.db")
    try:
        cursor = conn.execute(
            "DELETE FROM payments WHERE id = ? AND user_id = ?",
            (payment_id, current_user.id),
        )
        conn.commit()
    finally:
        conn.close()
    if cursor.rowcount == 0:
        abort(404)
    return jsonify({"deleted": payment_id})
