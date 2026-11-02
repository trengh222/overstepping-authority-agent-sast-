import sqlite3

from flask import Flask, jsonify, request
from flask_login import login_required

app = Flask(__name__)


@app.route("/api/addresses/<int:address_id>", methods=["PUT"])
@login_required
def update_address(address_id):
    payload = request.json or {}
    conn = sqlite3.connect("app.db")
    try:
        conn.execute(
            "UPDATE addresses SET line1 = ?, city = ? WHERE id = ?",
            (payload.get("line1"), payload.get("city"), address_id),
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"updated": address_id})
