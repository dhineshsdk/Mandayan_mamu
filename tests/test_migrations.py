"""The Alembic migrations must build exactly the schema the models describe."""

from alembic import command

from sutra.app import migrate


def test_migrations_match_models(tmp_path):
    url = f"sqlite:///{tmp_path / 'm.db'}"
    migrate.upgrade(url)
    command.check(migrate.config(url))  # raises if autogenerate would produce any change
