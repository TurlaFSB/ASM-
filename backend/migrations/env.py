"""Alembic environment. The database URL comes from backend.config (env vars)."""
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

from backend.config import settings
from backend.db import Base
# Import every model module so Base.metadata is complete (autogenerate relies on this)
import backend.models  # noqa: F401
from backend.models import schedule, audit_log, user  # noqa: F401

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(url=settings.database_url, target_metadata=target_metadata,
                      literal_binds=True, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(settings.database_url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
