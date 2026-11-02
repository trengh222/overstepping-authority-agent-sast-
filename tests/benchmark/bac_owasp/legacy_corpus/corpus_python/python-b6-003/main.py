import sqlite3

from fastapi import APIRouter, Depends, FastAPI, HTTPException
from pydantic import BaseModel

from security import get_current_user

app = FastAPI()
router = APIRouter()


class AccountOut(BaseModel):
    id: int
    owner_id: int
    email: str
    phone: str
    api_token: str
    password_hash: str


@router.get("/api/accounts/{account_id}")
def account_detail(
    account_id: int,
    current_user: int = Depends(get_current_user),
):
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT id, owner_id, email, phone, api_token, password_hash "
            "FROM accounts WHERE id = ?",
            (account_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404)
    if row["owner_id"] != current_user:
        raise HTTPException(status_code=403)
    return AccountOut(**dict(row)).model_dump()


app.include_router(router)
