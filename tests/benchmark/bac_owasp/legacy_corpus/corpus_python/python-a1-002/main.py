import sqlite3

from fastapi import APIRouter, Depends, FastAPI, HTTPException

from security import get_current_user

app = FastAPI()
router = APIRouter()


@router.get("/api/invoices/{invoice_id}")
def read_invoice(
    invoice_id: int,
    current_user: int = Depends(get_current_user),
):
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT id, user_id, total, status FROM invoices WHERE id = ?",
            (invoice_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404)
    return dict(row)


app.include_router(router)
