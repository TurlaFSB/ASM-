from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from backend.config import settings

engine = create_engine(settings.database_url)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

# Untrusted scan data must never carry NUL bytes into PostgreSQL.
from backend.db_sanitize import install as _install_sanitizer  # noqa: E402
_install_sanitizer()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()