import sqlite3

from fastapi import Depends, Header, HTTPException


def get_current_user(token: str | None = Header(default=None)) -> int:
    if not token:
        raise HTTPException(status_code=401)
    return int(token)


def require_admin(user_id: int = Depends(get_current_user)) -> int:
    conn = sqlite3.connect("app.db")
    try:
        row = conn.execute(
            "SELECT role FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None or row[0] != "admin":
        raise HTTPException(status_code=403)
    return user_id
