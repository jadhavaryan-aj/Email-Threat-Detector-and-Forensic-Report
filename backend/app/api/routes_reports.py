from fastapi import APIRouter, Depends, HTTPException, Response
from sqlmodel import Session

from app.db import get_session
from app.services.report_service import generate_case_report_pdf

router = APIRouter(prefix="/api/cases", tags=["reports"])


@router.get("/{case_id}/report")
def get_case_report(case_id: int, session: Session = Depends(get_session)):
    pdf_bytes = generate_case_report_pdf(session, case_id)
    if pdf_bytes is None:
        raise HTTPException(status_code=404, detail="Case not found or report could not be generated")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="case_{case_id}_forensic_report.pdf"'},
    )
