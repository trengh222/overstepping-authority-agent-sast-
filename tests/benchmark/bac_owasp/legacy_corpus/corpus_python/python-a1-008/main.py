from fastapi import APIRouter, Depends, FastAPI, HTTPException

from security import get_current_user
from service import ReportService

app = FastAPI()
router = APIRouter()
reports = ReportService()


@router.get("/api/reports/{report_id}")
def report_detail(
    report_id: int,
    current_user: int = Depends(get_current_user),
):
    report = reports.fetch(report_id)
    if report is None:
        raise HTTPException(status_code=404)
    return report


app.include_router(router)
