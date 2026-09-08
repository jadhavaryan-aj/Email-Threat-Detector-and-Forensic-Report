from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile
from sqlmodel import Session

from app.db import get_session
from app.services.ingestion_service import ingest_email

router = APIRouter(prefix="/api/cases", tags=["ingest"])

# PS section 22 (security): uploaded files are untrusted input. A hand-written phishing
# .eml is at most a few KB; this generously covers real-world messages with attachments
# while ruling out a multi-GB upload used purely to exhaust memory/disk.
_MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
_CHUNK_SIZE = 1024 * 1024


async def _read_bounded(file: UploadFile) -> bytes:
    """Reads in chunks and aborts as soon as the limit is exceeded, rather than
    buffering an arbitrarily large body fully into memory before checking its size."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(_CHUNK_SIZE)
        if not chunk:
            break
        total += len(chunk)
        if total > _MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail=f"File exceeds the {_MAX_UPLOAD_BYTES // (1024 * 1024)}MB limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _sanitize_source_url(value: str) -> str:
    """source_url is stored and later rendered as a clickable link on the
    dashboard — only accept http(s) so a crafted upload can't smuggle a
    javascript:/data: URI into what's effectively a stored link."""
    value = (value or "").strip()
    if value.lower().startswith(("http://", "https://")):
        return value
    return ""


@router.post("/upload")
async def upload_email(
    file: UploadFile, source_url: str = Form(default=""), session: Session = Depends(get_session)
):
    filename = file.filename or ""
    if not filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")

    raw_bytes = await _read_bounded(file)
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    try:
        email_analysis = ingest_email(session, raw_bytes, filename, source_url=_sanitize_source_url(source_url))
    except HTTPException:
        raise
    except Exception:
        # Malformed/unusual MIME structure must degrade to a clean 400, never a raw
        # 500 with an internal stack trace (PS section 25/22).
        session.rollback()
        raise HTTPException(status_code=400, detail="Could not parse or analyze this email") from None

    return {
        "case_id": email_analysis.case_id,
        "email_analysis_id": email_analysis.id,
        "status": "analyzed",
    }
