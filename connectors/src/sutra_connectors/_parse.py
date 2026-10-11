"""Small, strict parsers for the date and number formats the scanner APIs return."""

from __future__ import annotations

import re
from datetime import datetime, timezone

_FRACTION = re.compile(r"\.(\d+)")


def iso_datetime(value: object) -> datetime | None:
    """ISO-8601 text such as ``2026-10-01T06:00:00Z`` or ``2026-10-01T06:00:00.123456+05:30``; naive means UTC."""
    if value in (None, ""):
        return None
    text = str(value).strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    # Python 3.10's fromisoformat accepts only 3 or 6 fraction digits.
    text = _FRACTION.sub(lambda m: "." + (m[1] + "000000")[:6], text, count=1)
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def epoch_datetime(value: object) -> datetime | None:
    """Unix seconds, as a number or a string of digits. 0, -1 and empty mean "never"."""
    if value in (None, ""):
        return None
    try:
        seconds = int(str(value).strip())
    except ValueError:
        return None
    if seconds <= 0:
        return None
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


def to_epoch(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def score(value: object) -> float | None:
    """A CVSS score; empty, unparseable or negative values are None."""
    if value in (None, ""):
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if f >= 0 else None


def unique(values) -> tuple[str, ...]:
    """Non-empty strings, stripped, first occurrence kept, order preserved."""
    seen: dict[str, None] = {}
    for v in values:
        v = str(v or "").strip()
        if v and v not in seen:
            seen[v] = None
    return tuple(seen)
