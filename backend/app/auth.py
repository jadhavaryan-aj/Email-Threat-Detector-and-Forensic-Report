"""Lightweight shared-secret gate for /api/* routes. Optional by design — if
BACKEND_API_KEY is unset, the API stays fully open, matching every other
optional setting in this app (ABUSEIPDB_API_KEY, ANTHROPIC_API_KEY, ...) so a
fresh clone or local demo never requires configuration. Set it in .env before
exposing the API beyond localhost."""

from fastapi import Header, HTTPException, status

from app.config import settings


async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    if not settings.backend_api_key:
        return
    if x_api_key != settings.backend_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API key")
