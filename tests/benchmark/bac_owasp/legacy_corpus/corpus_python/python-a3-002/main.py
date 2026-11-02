import sqlite3

from fastapi import APIRouter, FastAPI

app = FastAPI()
router = APIRouter()


@router.get("/api/reports")
def all_reports():
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, owner_id, title, body FROM reports"
        ).fetchall()
    finally:
        conn.close()
    return [dict(row) for row in rows]


app.include_router(router)
