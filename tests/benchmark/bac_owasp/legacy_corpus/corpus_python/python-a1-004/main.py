from fastapi import APIRouter, Depends, FastAPI

from security import get_current_user
from store import list_messages

app = FastAPI()
router = APIRouter()


@router.get("/api/messages")
def message_inbox(
    user_id: int,
    current_user: int = Depends(get_current_user),
):
    return list_messages(user_id)


app.include_router(router)
