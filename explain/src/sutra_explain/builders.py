"""Build fact sets from the app's analysis payload (the JSON of ``sutra.views.payload``).

Only typed values go in. Titles, hostnames, site and process names become node *labels*, which people see and models
never do. The reader's categories stand in for finding titles.
"""

from __future__ import annotations

from typing import Any, Mapping

from .nodes import FactSet, Node
from .reader import RawText, RuleReader, Typed

CRORE = 10_000_000
LAKH = 100_000
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
EXPL_RANK = {"active": 2, "poc": 1, "none": 0}


def rupees(amount: float) -> str:
    """₹4.2 crore, ₹18.5 lakh or ₹45,000 (the same form the app shows)."""
    if amount >= CRORE:
        return f"₹{amount / CRORE:,.1f} crore"
    if amount >= LAKH:
        return f"₹{amount / LAKH:,.1f} lakh"
    return f"₹{round(amount):,}"


def _pct(x: float) -> int:
    return round(float(x) * 100)


def _rc_fields(rc: Mapping[str, Any]) -> dict[str, Any]:
    cves = rc.get("cves", [])
    f: dict[str, Any] = {
        "kind": rc["kind"], "ssvc": rc["ssvc"], "exploitation": rc["exploitation"], "exposure": rc["exposure"],
        "human_impact": rc["human_impact"], "max_severity": rc["max_severity"], "hosts": int(rc["hosts"]),
        "findings": int(rc["findings"]), "ale_label": rupees(rc["ale"]), "ale_p10_label": rupees(rc["ale_p10"]),
        "ale_p90_label": rupees(rc["ale_p90"]), "cea_overdue": int(rc["cea_overdue"]), "is_ot": bool(rc["is_ot"]),
        "cve_count": len(cves),
        "cves_active": sum(1 for c in cves if c.get("exploitation") == "active"),
        "cves_poc": sum(1 for c in cves if c.get("exploitation") == "poc"),
    }
    if rc.get("earliest_due"):
        f["earliest_due"] = rc["earliest_due"]
    return f


def read_findings(payload: Mapping[str, Any], finding_ids: list[str], reader=None) -> dict[str, Typed]:
    raws = [RawText(fid, payload["findings"][fid]["title"], "", payload["findings"][fid]["kind"])
            for fid in finding_ids if fid in payload["findings"]]
    return (reader or RuleReader()).read(raws)


def root_cause_facts(payload: Mapping[str, Any], rc_id: str, typed: Mapping[str, Typed] | None = None,
                     max_hosts: int = 12, max_findings: int = 12, max_cves: int = 5) -> FactSet:
    rc = next((r for r in payload["root_causes"] if r["id"] == rc_id), None)
    if rc is None:
        raise KeyError(f"no root cause {rc_id}")
    typed = typed if typed is not None else read_findings(payload, rc["finding_ids"])
    facts = FactSet(rc_id)
    fields = _rc_fields(rc)
    fields["injection_suspects"] = sum(1 for fid in rc["finding_ids"] if typed.get(fid) and typed[fid].suspicious)
    hosts = sorted((payload["assets"][a] for a in rc["asset_ids"] if a in payload["assets"]),
                   key=lambda a: (-a["criticality"], a["id"]))
    members = sorted((payload["findings"][f] for f in rc["finding_ids"] if f in payload["findings"]),
                     key=lambda f: (-SEV_RANK[f["severity"]], -(f["cvss"] or 0), f["id"]))
    # The model is told how much the nodes below cover, so it can say "12 of 40" and not claim more.
    fields["hosts_total"], fields["findings_total"] = len(hosts), len(members)
    facts.add(Node("R1", rc_id, "root_cause", rc["title"], fields))

    for i, a in enumerate(hosts[:max_hosts], 1):
        facts.add(Node(f"A{i}", a["id"], "asset", a["hostname"], {
            "zone": a["zone"], "criticality": int(a["criticality"]), "is_ot": bool(a["is_ot"]),
            "safety_critical": bool(a["safety"]), "in_cmdb": bool(a["in_cmdb"]),
            "scanned_by_count": len(a["scanned_by"])}))
    for i, f in enumerate(members[:max_findings], 1):
        t = typed.get(f["id"]) or Typed("other", False, "rules")
        fl: dict[str, Any] = {"severity": f["severity"], "finding_kind": f["kind"], "category": t.category,
                              "cve_count": len(f["cves"])}
        if f["cvss"] is not None:
            fl["cvss"] = float(f["cvss"])
        facts.add(Node(f"F{i}", f["id"], "finding", f["title"], fl))
    cves = sorted(rc.get("cves", []), key=lambda c: (-EXPL_RANK.get(c.get("exploitation", "none"), 0), c["id"]))
    for i, c in enumerate(cves[:max_cves], 1):
        fl = {"cve": c["id"], "exploitation": c.get("exploitation", "none")}
        if isinstance(c.get("epss"), (int, float)):
            fl["epss"] = float(c["epss"])
        facts.add(Node(f"C{i}", c["id"], "cve", c["id"], fl))
    return facts


def board_facts(payload: Mapping[str, Any], top_n: int = 5, unowned: int | None = None,
                typed: Mapping[str, Typed] | None = None) -> FactSet:
    facts = FactSet(payload["org"])
    h, cov, pl = payload["headline"], payload["coverage"], payload["portfolio_labels"]
    ssvc = h["ssvc"]
    facts.add(Node("B1", "portfolio", "portfolio", payload["org"], {
        "ale_label": pl["ale_mean"], "ale_p10_label": pl["ale_p10"], "ale_p90_label": pl["ale_p90"],
        "findings": int(h["findings"]), "root_causes": int(h["root_causes"]), "top_n": int(h["top_n"]),
        "top_findings_share": _pct(h["top_findings_share"]), "top_risk_share": _pct(h["top_risk_share"]),
        "ssvc_act": int(ssvc.get("Act", 0)), "ssvc_attend": int(ssvc.get("Attend", 0)),
        "ssvc_track_star": int(ssvc.get("Track*", 0)), "ssvc_track": int(ssvc.get("Track", 0)),
        "cea_overdue": int(h["cea_overdue"]), "cea_overdue_closed_by_top": int(h["cea_overdue_closed_by_top"])}))
    n = lambda v: len(v) if isinstance(v, (list, tuple)) else int(v)  # noqa: E731 - payload or board shape
    cf = {"cmdb_assets": int(cov["cmdb_assets"]), "scanned_assets": int(cov["scanned_assets"]),
          "unscanned": n(cov["unscanned"]), "unknown": n(cov["unknown"]), "inferred_images": n(cov["inferred_images"])}
    if unowned is not None:
        cf["unowned"] = int(unowned)
    facts.add(Node("K1", "coverage", "coverage", "Coverage", cf))
    for i, rc in enumerate(payload["root_causes"][:top_n], 1):
        fl = _rc_fields(rc)
        fl["rank"] = i
        suspects = 0
        if typed is not None and "finding_ids" in rc:
            suspects = sum(1 for fid in rc["finding_ids"] if typed.get(fid) and typed[fid].suspicious)
        fl["injection_suspects"] = suspects
        facts.add(Node(f"R{i}", rc["id"], "root_cause", rc["title"], fl))
    for i, s in enumerate(payload.get("risk_by_site", [])[:3], 1):
        facts.add(Node(f"S{i}", s["name"], "site", s["name"], {"ale_label": s["label"], "rank": i}))
    for i, s in enumerate(payload.get("risk_by_process", [])[:3], 1):
        facts.add(Node(f"P{i}", s["name"], "process", s["name"], {"ale_label": s["label"], "rank": i}))
    return facts
