"""SSVC triage and FAIR-style rupee risk for each root cause.

Every assumption lives in ASSUMPTIONS so a design partner can argue with a number, change it,
and rerun. The figures are hypotheses for a demo, not calibrated loss data.
"""

from __future__ import annotations

import json
import math
import random
from datetime import date
from pathlib import Path

from .model import Asset, Finding, RootCause

ASSUMPTIONS = {
    # Threat event frequency: attempts per year against this weakness, as PERT (min, most likely, max).
    "tef_per_year": {"active": (1.0, 4.0, 12.0), "poc": (0.2, 1.0, 3.0), "none": (0.02, 0.1, 0.4)},
    # Chance one attempt succeeds, by the most exposed zone the root cause touches.
    "vulnerability_by_zone": {"internet": 0.5, "dmz": 0.3, "corp": 0.15, "ot-l3": 0.06, "ot-l2": 0.04,
                              "ot-l1": 0.03},
    # Hours a business process is down after a successful attack.
    "outage_hours": {"it": (4, 16, 72), "ot": (12, 48, 168)},
    "default_inr_per_hour": 25_000,  # hosts missing from the CMDB have no business process yet
    "response_cost_inr": (200_000, 600_000, 2_000_000),
    "breach_cost_inr": (2_000_000, 15_000_000, 80_000_000),  # personal data (DPDP exposure)
    "breach_probability": 0.3,
    "ot_secondary_inr": (1_000_000, 5_000_000, 30_000_000),  # equipment, restart, regulator
    "iterations": 3000,
    "seed": 11,
    # CEA fix clock (vendor summary in the plan; confirm against the gazette text before external use).
    "cea_due_days": {"critical": 30, "high": 30, "medium": 90, "low": 90, "info": 90},
}

EXPOSURE = {"internet": "open", "dmz": "controlled", "corp": "controlled", "ot-l3": "small", "ot-l2": "small",
            "ot-l1": "small"}
ZONE_RANK = ["ot-l1", "ot-l2", "ot-l3", "corp", "dmz", "internet"]
SSVC_ORDER = {"Act": 0, "Attend": 1, "Track*": 2, "Track": 3}


def load_intel(path: Path | None = None) -> dict:
    path = path or Path(__file__).parent / "data" / "threat_intel.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


def _pert(rng: random.Random, lo: float, mode: float, hi: float) -> float:
    if hi <= lo:
        return lo
    a = 1 + 4 * (mode - lo) / (hi - lo)
    b = 1 + 4 * (hi - mode) / (hi - lo)
    return lo + rng.betavariate(a, b) * (hi - lo)


def _exploitation(rc: RootCause, intel: dict) -> str:
    states = {intel.get(c, {}).get("exploitation", "none") for c in rc.cves}
    if "active" in states:
        return "active"
    if "poc" in states or rc.kind == "shared-credential":
        return "poc"  # a working shared or default password needs no exploit code
    return "none"


def _human_impact(assets: list[Asset]) -> str:
    if any(a.safety_critical for a in assets):
        return "very high"
    if any(a.criticality >= 4 or a.personal_data for a in assets):
        return "high"
    if any(a.criticality >= 3 for a in assets):
        return "medium"
    return "low"


def ssvc(exploitation: str, exposure: str, impact: str) -> str:
    """A simplified CISA SSVC deployer decision."""
    high_impact = impact in ("high", "very high")
    if exploitation == "active":
        return "Act" if exposure == "open" or impact == "very high" else "Attend"
    if exploitation == "poc":
        return "Attend" if exposure == "open" or high_impact else "Track*"
    return "Track*" if exposure == "open" and high_impact else "Track"


def assess(rcs: list[RootCause], assets: dict[str, Asset], findings: list[Finding], intel: dict,
           as_of: date) -> dict:
    A = ASSUMPTIONS
    rng = random.Random(A["seed"])
    by_id = {f.finding_id: f for f in findings}
    iters = A["iterations"]
    portfolio = [0.0] * iters

    for rc in rcs:
        hosts = [assets[a] for a in rc.asset_ids]
        top_zone = max((h.zone for h in hosts), key=lambda z: ZONE_RANK.index(z) if z in ZONE_RANK else 3)
        rc.exploitation = _exploitation(rc, intel)
        rc.exposure = EXPOSURE.get(top_zone, "controlled")
        rc.human_impact = _human_impact(hosts)
        rc.ssvc = ssvc(rc.exploitation, rc.exposure, rc.human_impact)

        vuln = min(0.95, A["vulnerability_by_zone"].get(top_zone, 0.15) * (1 + 0.5 * math.log10(len(hosts))))
        per_process: dict[str, float] = {}
        for h in hosts:
            name = h.business_process or f"(unmapped) {h.hostname}"
            per_process[name] = max(per_process.get(name, 0), h.inr_per_hour or A["default_inr_per_hour"])
        rates = sorted(per_process.values(), reverse=True)
        inr_per_hour = rates[0] + 0.25 * sum(rates[1:])
        outage = A["outage_hours"]["ot" if rc.is_ot else "it"]
        pii = any(h.personal_data for h in hosts)

        samples = []
        for i in range(iters):
            lef = _pert(rng, *A["tef_per_year"][rc.exploitation]) * vuln
            lm = _pert(rng, *outage) * inr_per_hour + _pert(rng, *A["response_cost_inr"])
            if pii:
                lm += A["breach_probability"] * _pert(rng, *A["breach_cost_inr"])
            if rc.is_ot:
                lm += _pert(rng, *A["ot_secondary_inr"])
            ale = lef * lm
            samples.append(ale)
            portfolio[i] += ale
        samples.sort()
        rc.ale_mean = sum(samples) / iters
        rc.ale_p10 = samples[int(0.10 * iters)]
        rc.ale_p90 = samples[int(0.90 * iters)]
        rc.risk_inputs = {"top_zone": top_zone, "vulnerability": round(vuln, 3),
                          "tef_pert": A["tef_per_year"][rc.exploitation], "inr_per_hour_at_risk": round(inr_per_hour),
                          "processes": sorted(per_process), "outage_hours_pert": outage, "personal_data": pii}

        due = A["cea_due_days"]
        members = [by_id[fid] for fid in rc.finding_ids]
        rc.cea_overdue = sum(1 for f in members if f.first_seen and (as_of - f.first_seen).days > due[f.severity])

    portfolio.sort()
    return {"ale_mean": sum(portfolio) / iters, "ale_p10": portfolio[int(0.10 * iters)],
            "ale_p90": portfolio[int(0.90 * iters)], "iterations": iters}
