from fastapi import APIRouter, Depends, FastAPI

from deps import require_admin

app = FastAPI()
router = APIRouter()


@router.get("/api/admin/audit-logs")
def audit_logs(admin_id: int = Depends(require_admin)):
    return [{"id": 1, "actor": admin_id, "action": "role_changed"}]


app.include_router(router)
