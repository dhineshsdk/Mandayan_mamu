"""Maintenance windows, computed from the customer's policy rather than written by the model."""

from __future__ import annotations

from datetime import date, datetime, timedelta

from .inputs import MaintenancePolicy

SHUTDOWN_NOT_SET = "Shutdown slot not set: confirm the next planned shutdown with operations"


def it_windows(policy: MaintenancePolicy, as_of: date, count: int) -> list[str]:
    """The next ``count`` weekly windows strictly after ``as_of``, one per ring."""
    first = as_of + timedelta(days=(policy.weekday - as_of.weekday()) % 7 or 7)
    out = []
    for i in range(count):
        start = datetime.combine(first + timedelta(weeks=i), policy.start)
        end = start + timedelta(hours=policy.duration_hours)
        out.append(f"{start:%a %d %b %Y}, {start:%H:%M} to {end:%H:%M} {policy.timezone_label}")
    return out


def ot_window(policy: MaintenancePolicy, as_of: date) -> str | None:
    """The named plant shutdown, if operations has given one that is still ahead."""
    if policy.ot_shutdown and policy.ot_shutdown > as_of:
        return f"Planned shutdown {policy.ot_shutdown:%a %d %b %Y}"
    return None
