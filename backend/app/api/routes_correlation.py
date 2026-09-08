from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session

from app.db import get_session
from app.models.case import Case
from app.services.correlation_service import build_case_graph, find_shared_infrastructure

router = APIRouter(prefix="/api/cases", tags=["correlation"])


@router.get("/{case_id}/indicators")
def get_case_indicators(case_id: int, session: Session = Depends(get_session)):
    if session.get(Case, case_id) is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"shared_infrastructure": find_shared_infrastructure(session, case_id)}


@router.get("/{case_id}/graph")
def get_case_graph(case_id: int, session: Session = Depends(get_session)):
    if session.get(Case, case_id) is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return build_case_graph(session, case_id)
