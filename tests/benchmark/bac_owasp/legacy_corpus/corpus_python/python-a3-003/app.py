import csv
import io
import sqlite3

from flask import Flask, Response

app = Flask(__name__)


@app.route("/api/payments/export", methods=["GET"])
def export_payments():
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, user_id, amount, created_at FROM payments"
        ).fetchall()
    finally:
        conn.close()
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["id", "user_id", "amount", "created_at"])
    writer.writerows([tuple(row) for row in rows])
    return Response(out.getvalue(), mimetype="text/csv")
