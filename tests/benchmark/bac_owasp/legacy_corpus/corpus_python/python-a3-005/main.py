from fastapi import APIRouter, Depends, FastAPI

from security import get_current_user

app = FastAPI()
router = APIRouter(dependencies=[Depends(get_current_user)])


@router.get("/api/audit/events")
def audit_events():
    return [{"id": 1, "event": "role_changed"}]


app.include_router(router)
