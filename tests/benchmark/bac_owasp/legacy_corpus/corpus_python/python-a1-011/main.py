from fastapi import APIRouter, Depends, FastAPI, HTTPException

from security import get_current_user
from service import InvoiceService

app = FastAPI()
router = APIRouter()
invoices = InvoiceService()


@router.get("/api/billing/invoices/{invoice_id}")
def invoice_detail(
    invoice_id: int,
    current_user: int = Depends(get_current_user),
):
    invoice = invoices.get_for_user(invoice_id, current_user)
    if invoice is None:
        raise HTTPException(status_code=404)
    return invoice


app.include_router(router)
