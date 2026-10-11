from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from sutra_compliance import Audit, AuditFinding, Entity, EntityRecords, load_rule_pack

IST = timezone(timedelta(hours=5, minutes=30))
BUNDLED = Path(__file__).resolve().parents[1] / "src" / "sutra_compliance" / "rules" / "cea_cs_2026.toml"


def at(y: int, m: int, d: int, hh: int = 12, mm: int = 0) -> datetime:
    return datetime(y, m, d, hh, mm, tzinfo=IST)


@pytest.fixture(scope="session")
def pack():
    return load_rule_pack()


@pytest.fixture
def pack_text() -> str:
    return BUNDLED.read_text(encoding="utf-8")


@pytest.fixture
def load_modified(tmp_path):
    """Load the bundled pack after a textual edit, the way a person would correct it."""

    def _load(old: str, new: str):
        text = BUNDLED.read_text(encoding="utf-8")
        assert old in text, f"fixture edit target not found: {old!r}"
        path = tmp_path / "pack.toml"
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
        return load_rule_pack(path)

    return _load


def generator(capacity: float | None = 600) -> Entity:
    return Entity("ent-1", "Example Thermal Station", "generator", capacity)


_DEFAULT = object()


def audit(audit_id="A1", started=date(2027, 4, 5), report=_DEFAULT, closure=None,
          auditor="Auditor One", status="cert_in_empanelled", **kw) -> Audit:
    """An audit; the report defaults to 35 days after the start (10 May 2027 for the default start)."""
    if report is _DEFAULT:
        report = started + timedelta(days=35)
    return Audit(audit_id, "ent-1", auditor, status, started, report, closure, **kw)


def finding(fid="F1", severity="critical", audit_id="A1", **kw) -> AuditFinding:
    return AuditFinding(fid, audit_id, severity, f"{severity} finding {fid}", **kw)


def records(**kw) -> EntityRecords:
    kw.setdefault("entity", generator())
    return EntityRecords(**kw)
