from fastapi import APIRouter, Depends, FastAPI
from pydantic import BaseModel

from security import get_current_user
from service import TicketService

app = FastAPI()
router = APIRouter()
tickets = TicketService()


class BulkCloseRequest(BaseModel):
    ticket_ids: list[int]


@router.post("/api/tickets/bulk-close")
def bulk_close(
    payload: BulkCloseRequest,
    current_user: int = Depends(get_current_user),
):
    return {"closed": tickets.close_many(payload.ticket_ids)}


app.include_router(router)
