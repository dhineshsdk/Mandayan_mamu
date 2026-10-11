"""Serialize an analysis into the JSON the web app renders: board, queue, assets, owners."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from .money import inr
from .pipeline import Result
from .report import TOP_N, headline
from .risk import ASSUMPTIONS


def _asset(a) -> dict:
    return {"id": a.asset_id, "hostname": a.hostname, "ip": a.ip, "site": a.site, "zone": a.zone, "os": a.os,
            "owner": a.owner, "process": a.business_process, "inr_per_hour": a.inr_per_hour,
            "criticality": a.criticality, "image": a.image, "image_source": a.image_source,
            "template": a.config_template, "is_ot": a.is_ot, "safety": a.safety_critical, "pii": a.personal_data,
            "in_cmdb": a.in_cmdb, "scanned_by": sorted(a.scanned_by)}


def _due(f) -> str | None:
    if not f.first_seen:
        return None
    return (f.first_seen + timedelta(days=ASSUMPTIONS["cea_due_days"][f.severity])).isoformat()


def payload(res: Result, intel: dict) -> dict:
    findings = {f.finding_id: f for f in res.findings}
    rcs = []
    for r in res.root_causes:
        dues = [d for d in (_due(findings[fid]) for fid in r.finding_ids) if d]
        rcs.append({
            "id": r.rc_id, "kind": r.kind, "key": r.key, "title": r.title, "fix": r.fix, "executor": r.executor,
            "is_ot": r.is_ot, "hosts": len(r.asset_ids), "findings": len(r.finding_ids),
            "asset_ids": r.asset_ids, "finding_ids": r.finding_ids, "max_severity": r.max_severity,
            "max_cvss": r.max_cvss, "ssvc": r.ssvc, "exploitation": r.exploitation, "exposure": r.exposure,
            "human_impact": r.human_impact, "ale": round(r.ale_mean), "ale_p10": round(r.ale_p10),
            "ale_p90": round(r.ale_p90), "ale_label": inr(r.ale_mean), "risk_inputs": r.risk_inputs,
            "cea_overdue": r.cea_overdue, "earliest_due": min(dues) if dues else None,
            "cves": [{"id": c, **intel.get(c, {"exploitation": "none"})} for c in r.cves],
            "owners": sorted({res.assets[a].owner for a in r.asset_ids if res.assets[a].owner}),
            "sites": sorted({res.assets[a].site for a in r.asset_ids if res.assets[a].site}),
        })

    # Spread each root cause's risk over the business processes it touches, weighted by ₹ per hour.
    by_process: dict[str, float] = defaultdict(float)
    by_site: dict[str, float] = defaultdict(float)
    for r in res.root_causes:
        hosts = [res.assets[a] for a in r.asset_ids]
        weights: dict[tuple, float] = defaultdict(float)
        for h in hosts:
            weights[(h.business_process or "Not in CMDB", h.site or "Not in CMDB")] = max(
                weights[(h.business_process or "Not in CMDB", h.site or "Not in CMDB")], h.inr_per_hour or 1.0)
        total = sum(weights.values())
        for (proc, site), w in weights.items():
            by_process[proc] += r.ale_mean * w / total
            by_site[site] += r.ale_mean * w / total

    owners: dict[str, list] = defaultdict(list)
    for rc in rcs:
        for o in rc["owners"] or ["(no owner: not in CMDB)"]:
            mine = [a for a in rc["asset_ids"] if (res.assets[a].owner or "(no owner: not in CMDB)") == o]
            owners[o].append({"id": rc["id"], "title": rc["title"], "fix": rc["fix"], "ssvc": rc["ssvc"],
                              "ale": rc["ale"], "ale_label": rc["ale_label"], "my_hosts": len(mine),
                              "earliest_due": rc["earliest_due"], "is_ot": rc["is_ot"]})
    owner_list = sorted(({"owner": o, "tasks": sorted(t, key=lambda x: -x["ale"]),
                          "ale": sum(x["ale"] for x in t)} for o, t in owners.items()), key=lambda x: -x["ale"])

    h = headline(res)
    cov = res.coverage
    return {
        "org": res.org, "as_of": res.as_of.isoformat(), "sources": res.sources, "raw_rows": res.raw_rows,
        "portfolio": {k: round(v) if isinstance(v, float) else v for k, v in res.portfolio.items()},
        "portfolio_labels": {k: inr(res.portfolio[k]) for k in ("ale_mean", "ale_p10", "ale_p90")},
        "headline": {"findings": h["findings"], "root_causes": h["root_causes"], "top_n": TOP_N,
                     "top_findings_share": h["top_findings_share"], "top_risk_share": h["top_risk_share"],
                     "ssvc": dict(h["ssvc"]), "cea_overdue": h["cea_overdue"],
                     "cea_overdue_closed_by_top": h["cea_overdue_closed_by_top"]},
        "coverage": {"cmdb_assets": cov["cmdb_assets"], "scanned_assets": cov["scanned_assets"],
                     "multi_scanner_findings": cov["multi_scanner_findings"],
                     "unscanned": [a.asset_id for a in cov["unscanned"]],
                     "unknown": [a.asset_id for a in cov["unknown"]],
                     "inferred_images": [a.asset_id for a in cov["inferred_images"]]},
        "risk_by_process": sorted(({"name": k, "ale": round(v), "label": inr(v)} for k, v in by_process.items()),
                                  key=lambda x: -x["ale"]),
        "risk_by_site": sorted(({"name": k, "ale": round(v), "label": inr(v)} for k, v in by_site.items()),
                               key=lambda x: -x["ale"]),
        "root_causes": rcs,
        "assets": {a.asset_id: _asset(a) for a in res.assets.values()},
        "findings": {f.finding_id: {"id": f.finding_id, "asset_id": f.asset_id, "title": f.title,
                                    "severity": f.severity, "cvss": f.cvss, "cves": f.cves, "kind": f.kind,
                                    "package": f.package, "installed": f.installed, "fixed": f.fixed,
                                    "control": f.control, "credential_fp": f.credential_fp,
                                    "first_seen": f.first_seen.isoformat() if f.first_seen else None,
                                    "due": _due(f), "evidence": f.evidence[:600], "rc": f.root_cause_id,
                                    "sources": [s.__dict__ for s in f.sources]} for f in res.findings},
        "owners": owner_list,
        "assumptions": ASSUMPTIONS,
    }


def headline_check(res: Result, query: str, intel: dict) -> dict:
    """'Are we exposed?' Search CVE IDs, product names and titles across every finding."""
    q = query.strip().lower()
    if not q:
        return {"query": query, "hits": []}
    hits = [f for f in res.findings
            if any(q == c.lower() for c in f.cves) or q in f.title.lower() or q in f.package.lower()]
    rc_ids = sorted({f.root_cause_id for f in hits})
    assets = sorted({f.asset_id for f in hits})
    return {
        "query": query, "exposed": bool(hits), "findings": len(hits), "hosts": len(assets),
        "ot_hosts": sum(1 for a in assets if res.assets[a].is_ot),
        "internet_hosts": sum(1 for a in assets if res.assets[a].zone == "internet"),
        "root_causes": rc_ids, "asset_ids": assets,
        "intel": intel.get(query.strip().upper()),
        "unscanned_note": len(res.coverage["unscanned"]),
    }
