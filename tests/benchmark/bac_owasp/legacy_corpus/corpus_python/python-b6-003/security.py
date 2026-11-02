from fastapi import Header, HTTPException


def get_current_user(token: str | None = Header(default=None)) -> int:
    if not token:
        raise HTTPException(status_code=401)
    return int(token)
