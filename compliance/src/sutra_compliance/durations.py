"""Durations written in regulation terms (months, weeks, days, hours) and calendar arithmetic on them."""

from __future__ import annotations

import calendar
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any

_UNITS = ("months", "weeks", "days", "hours")


def add_months(d: date, months: int) -> date:
    """Add calendar months. A day that does not exist in the target month moves to its last day."""
    index = d.year * 12 + (d.month - 1) + months
    year, month0 = divmod(index, 12)
    day = min(d.day, calendar.monthrange(year, month0 + 1)[1])
    return d.replace(year=year, month=month0 + 1, day=day)


@dataclass(frozen=True)
class Duration:
    months: int = 0
    weeks: int = 0
    days: int = 0
    hours: int = 0

    def __post_init__(self) -> None:
        for unit in _UNITS:
            value = getattr(self, unit)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"duration {unit} must be a non-negative integer, got {value!r}")
        if not any(getattr(self, unit) for unit in _UNITS):
            raise ValueError("duration must not be zero")

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> Duration:
        if not isinstance(raw, Mapping):
            raise ValueError(f"duration must be a table such as {{ months = 1 }}, got {raw!r}")
        unknown = set(raw) - set(_UNITS)
        if unknown:
            raise ValueError(f"unknown duration unit(s) {sorted(unknown)}; use {', '.join(_UNITS)}")
        return cls(**dict(raw))

    @property
    def has_time(self) -> bool:
        return self.hours > 0

    def after(self, start: date) -> date:
        """The calendar date this duration after ``start``. Durations with hours need a datetime."""
        if isinstance(start, datetime):
            raise TypeError("use after_datetime() for datetimes")
        if self.has_time:
            raise ValueError(f"{self} has an hours part and cannot be applied to a date")
        return add_months(start, self.months) + timedelta(weeks=self.weeks, days=self.days)

    def after_datetime(self, start: datetime) -> datetime:
        if start.tzinfo is None or start.utcoffset() is None:
            raise ValueError("datetimes must be timezone-aware")
        moved = datetime.combine(add_months(start.date(), self.months), start.timetz())
        return moved + timedelta(weeks=self.weeks, days=self.days, hours=self.hours)

    def to_dict(self) -> dict[str, int]:
        return {unit: getattr(self, unit) for unit in _UNITS if getattr(self, unit)}

    def __str__(self) -> str:
        parts = []
        for unit in _UNITS:
            value = getattr(self, unit)
            if value:
                parts.append(f"{value} {unit[:-1] if value == 1 else unit}")
        return ", ".join(parts)
