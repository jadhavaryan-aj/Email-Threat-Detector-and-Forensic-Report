from fastapi import APIRouter, Depends
from sqlmodel import Session

from app.db import get_session
from app.services.dashboard_service import get_dashboard_stats

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats")
def dashboard_stats(session: Session = Depends(get_session)):
    return get_dashboard_stats(session)
