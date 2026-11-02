from fastapi import APIRouter, Depends, FastAPI

from security import get_current_user
from service import delete_user

app = FastAPI()
router = APIRouter()


@router.delete("/api/admin/users/{user_id}")
def remove_user(
    user_id: int,
    current_user: int = Depends(get_current_user),
):
    delete_user(user_id)
    return {"deleted": user_id}


app.include_router(router)
