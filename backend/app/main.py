from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import routes_cases, routes_correlation, routes_dashboard, routes_ingest, routes_reports
from app.auth import require_api_key
from app.config import settings
from app.db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="SIH26106 - AI Email Threat Detection Platform", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_origin_regex=r"^chrome-extension://.*$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_auth = [Depends(require_api_key)]
app.include_router(routes_ingest.router, dependencies=_auth)
app.include_router(routes_cases.router, dependencies=_auth)
app.include_router(routes_correlation.router, dependencies=_auth)
app.include_router(routes_dashboard.router, dependencies=_auth)
app.include_router(routes_reports.router, dependencies=_auth)


@app.get("/health")
def health():
    return {"status": "ok"}
