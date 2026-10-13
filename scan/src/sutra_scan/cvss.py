"""CVSS v3.0 and v3.1 base scores from a vector string (FIRST CVSS v3.1 specification, section 7)."""

from __future__ import annotations

import math
import re

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_VECTOR = re.compile(r"^CVSS:3\.(?P<minor>[01])/(?P<metrics>(?:[A-Z]+:[A-Z]/?)+)$")


def _roundup(x: float, minor: str) -> float:
    if minor == "0":
        return math.ceil(x * 10) / 10
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def base_score(vector: str) -> float | None:
    """The base score, or ``None`` when the string is not a complete CVSS v3 vector (v2 and v4 are not scored)."""
    m = _VECTOR.match((vector or "").strip())
    if not m:
        return None
    try:
        metrics = dict(part.split(":") for part in m["metrics"].split("/") if part)
        scope_changed = {"U": False, "C": True}[metrics["S"]]
        iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
        impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if scope_changed else 6.42 * iss
        pr = (_PR_C if scope_changed else _PR_U)[metrics["PR"]]
        exploit = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr * _UI[metrics["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    raw = 1.08 * (impact + exploit) if scope_changed else impact + exploit
    return _roundup(min(raw, 10), m["minor"])


def rating(score: float | None) -> str:
    """The qualitative severity rating scale (specification section 5)."""
    if score is None:
        return ""
    for floor, name in ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low")):
        if score >= floor:
            return name
    return "info"
