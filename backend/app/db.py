from pathlib import Path

from sqlmodel import SQLModel, Session, create_engine

from app.config import settings

# SQLite file path lives relative to backend/ — ensure the data/ dir exists
# before the engine tries to create the file.
if settings.database_url.startswith("sqlite:///./"):
    db_file = Path(settings.database_url.replace("sqlite:///./", "", 1))
    db_file.parent.mkdir(parents=True, exist_ok=True)

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, echo=False, connect_args=connect_args)


def init_db() -> None:
    from app.models import (  # noqa: F401  (ensures every table is registered)
        case,
        correlation,
        forensics,
        intelligence,
        signal,
    )

    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session
