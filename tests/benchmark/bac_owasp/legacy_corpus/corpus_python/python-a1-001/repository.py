import sqlite3


def find_order(order_id):
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT id, user_id, status, total FROM orders WHERE id = ?",
            (order_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()
