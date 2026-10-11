"""Database migrations (Alembic), run programmatically so an install needs no alembic.ini."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

MIGRATIONS = Path(__file__).resolve().parent / "migrations"


def config(database_url: str) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS))
    cfg.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return cfg


def upgrade(database_url: str, revision: str = "head") -> None:
    command.upgrade(config(database_url), revision)


def revision(database_url: str, message: str) -> None:
    """Developer helper: autogenerate a new migration from the models."""
    command.revision(config(database_url), message=message, autogenerate=True)
