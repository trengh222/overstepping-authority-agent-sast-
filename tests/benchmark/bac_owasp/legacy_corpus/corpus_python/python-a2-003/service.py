import sqlite3


def delete_user(user_id):
    conn = sqlite3.connect("app.db")
    try:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()
