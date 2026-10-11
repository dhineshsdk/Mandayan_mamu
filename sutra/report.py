"""Outputs: a one-page board summary (HTML, prints to A4) plus the receipts behind every number."""

from __future__ import annotations

import csv
import html
import json
from collections import Counter
from pathlib import Path

from .money import inr
from .pipeline import Result
from .risk import ASSUMPTIONS

TOP_N = 10
KIND_LABEL = {"base-image": "Base image", "package": "Package", "config-template": "Config template",
              "shared-credential": "Shared credential", "fleet-config": "Fleet config", "fleet": "Fleet",
              "single": "Single"}


def _e(s) -> str:
    return html.escape(str(s))


def headline(res: Result) -> dict:
    rcs = res.root_causes
    top = rcs[:TOP_N]
    n_find = len(res.findings)
    total = sum(r.ale_mean for r in rcs) or 1.0
    overdue = sum(r.cea_overdue for r in rcs)
    return {
        "findings": n_find,
        "root_causes": len(rcs),
        "top_findings_share": sum(len(r.finding_ids) for r in top) / n_find,
        "top_risk_share": sum(r.ale_mean for r in top) / total,
        "ssvc": Counter(r.ssvc for r in rcs),
        "cea_overdue": overdue,
        "cea_overdue_rcs": sum(1 for r in rcs if r.cea_overdue),
        "cea_overdue_closed_by_top": sum(r.cea_overdue for r in top),
    }


def briefing_html(b: dict) -> str:
    """The quarterly briefing as a section of the board pack. ``b`` is an AI service result: every claim has already
    passed the citation checks, and the cited nodes are listed so a reader can follow each one."""
    by = (f"Written by an AI model ({_e(b['model'])}) and checked by Sutra against the figures above"
          if b["source"] == "ai" else "Written from fixed rules, with no AI model")
    parts = []
    for sec in b["sections"]:
        items = "".join(f"<li>{_e(c['text'])} <span class=\"cites\">[{_e(', '.join(x['ref'] for x in c['cites']))}]</span></li>"
                        for c in sec["claims"])
        parts.append(f"<h3>{_e(sec['title'])}</h3><ul>{items}</ul>")
    note = f" Model fallback: {_e(b['fallback_reason'])}." if b.get("fallback_reason") else ""
    return (f'<section class="briefing"><h2>Quarterly briefing</h2><div class="by">{by}.{note} Bracketed letters name the '
            f'figures a sentence rests on (B1 portfolio, K1 coverage, R root causes, S sites, P processes).</div>'
            f'{"".join(parts)}</section>')


def render_board_html(res: Result, briefing: dict | None = None) -> str:
    h = headline(res)
    cov = res.coverage
    top = res.root_causes[:TOP_N]
    crown_unscanned = [a for a in cov["unscanned"] if a.criticality >= 5]
    ot_unscanned = [a for a in cov["unscanned"] if a.is_ot]
    act = [r for r in res.root_causes if r.ssvc == "Act"]
    ot_top = [r for r in top if r.is_ot]

    rows = []
    for r in top:
        who = "OT: human-run, OEM approval" if r.is_ot else "IT: automatable after approval"
        rows.append(f"""
        <tr>
          <td class="id">{_e(r.rc_id)}</td>
          <td><div class="t">{_e(r.title)}</div><div class="fix">{_e(r.fix)}</div></td>
          <td>{_e(KIND_LABEL[r.kind])}</td>
          <td class="n">{len(r.asset_ids)}</td>
          <td class="n">{len(r.finding_ids)}</td>
          <td><span class="ssvc s-{_e(r.ssvc.replace('*', 'star'))}">{_e(r.ssvc)}</span></td>
          <td class="n money">{_e(inr(r.ale_mean))}</td>
          <td class="n">{r.cea_overdue or '–'}</td>
          <td class="who">{_e(who)}</td>
        </tr>""")

    asks = []
    if act:
        asks.append(f"<b>Approve emergency changes</b> for the {len(act)} root cause{'s' if len(act) > 1 else ''} "
                    f"rated Act ({', '.join(_e(r.rc_id) for r in act)}): actively exploited and exposed or "
                    f"safety-relevant. Together {_e(inr(sum(r.ale_mean for r in act)))} a year of expected loss.")
    if ot_top:
        asks.append(f"<b>Back the plant schedule</b>: {len(ot_top)} of the top {TOP_N} fixes are on OT and need OEM "
                    f"approval and a planned outage. Compensating controls (virtual patch, segmentation) hold the "
                    f"risk until then, and the CEA clock should show that state, not a red mark.")
    if cov["unscanned"]:
        asks.append(f"<b>Close the blind spots</b>: {len(cov['unscanned'])} registered assets are never scanned"
                    + (f", including {len(crown_unscanned)} crown-jewel systems" if crown_unscanned else "")
                    + (f" and {len(ot_unscanned)} OT devices" if ot_unscanned else "")
                    + ". Their risk is not in the figure above.")

    ssvc_chips = "".join(f'<span class="ssvc s-{k.replace("*", "star")}">{k}: {h["ssvc"].get(k, 0)}</span>'
                         for k in ("Act", "Attend", "Track*", "Track"))
    src = " · ".join(f"{_e(k)} ({v} detections)" for k, v in res.sources.items())
    p = res.portfolio

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Board Cyber Summary</title>
<style>
  :root {{ --ink:#1b1f24; --muted:#5b6470; --line:#dde1e6; --panel:#f5f7f9; --accent:#0b5cad;
          --act:#b42318; --attend:#b54708; --trackstar:#7a5af8; --track:#475467; }}
  @page {{ size: A4; margin: 11mm; }}
  * {{ box-sizing: border-box; }}
  body {{ font: 10.5px/1.38 "Segoe UI", system-ui, -apple-system, Roboto, Arial, sans-serif; color: var(--ink);
         background:#fff; margin: 0 auto; max-width: 820px; padding: 18px 16px; }}
  header {{ display:flex; justify-content:space-between; align-items:flex-end; border-bottom:2px solid var(--ink);
           padding-bottom:6px; gap: 12px; flex-wrap: wrap; }}
  h1 {{ font-size:19px; margin:0; letter-spacing:-.01em; }}
  .meta {{ color:var(--muted); font-size:10px; text-align:right; }}
  .synthetic {{ display:inline-block; background:#fef3f2; color:var(--act); border:1px solid #fecdca;
               border-radius:3px; padding:1px 6px; font-weight:600; font-size:9.5px; }}
  .kpis {{ display:grid; grid-template-columns: repeat(4, 1fr); gap:8px; margin:10px 0 8px; }}
  .kpi {{ background:var(--panel); border-radius:6px; padding:8px 10px; }}
  .kpi .label {{ color:var(--muted); font-size:9.5px; text-transform:uppercase; letter-spacing:.04em; }}
  .kpi .value {{ font-size:20px; font-weight:700; margin:2px 0 1px; font-variant-numeric: tabular-nums; }}
  .kpi .sub {{ color:var(--muted); font-size:9.5px; }}
  .strip {{ display:flex; gap:14px; flex-wrap:wrap; align-items:center; margin:2px 0 8px; color:var(--muted); }}
  .ssvc {{ display:inline-block; border-radius:3px; padding:0 5px; font-weight:600; font-size:9.5px; color:#fff;
          white-space:nowrap; }}
  .s-Act {{ background:var(--act); }} .s-Attend {{ background:var(--attend); }}
  .s-Trackstar {{ background:var(--trackstar); }} .s-Track {{ background:var(--track); }}
  h2 {{ font-size:12px; margin:10px 0 4px; }}
  table {{ width:100%; border-collapse:collapse; }}
  th {{ text-align:left; font-size:9px; color:var(--muted); text-transform:uppercase; letter-spacing:.03em;
       border-bottom:1px solid var(--ink); padding:3px 4px; }}
  td {{ border-bottom:1px solid var(--line); padding:4px; vertical-align:top; }}
  td.n, th.n {{ text-align:right; font-variant-numeric: tabular-nums; white-space:nowrap; }}
  td.id {{ color:var(--muted); white-space:nowrap; }}
  td .t {{ font-weight:600; }}
  td .fix {{ color:var(--muted); font-size:9.5px; }}
  td.money {{ font-weight:600; }}
  td.who {{ font-size:9.5px; color:var(--muted); width:92px; }}
  ul {{ margin:4px 0 0; padding-left:16px; }}
  .briefing h3 {{ font-size:11px; margin:8px 0 2px; }} .briefing .by, .cites {{ color:var(--muted); font-size:9.5px; }}
  li {{ margin-bottom:3px; }}
  footer {{ margin-top:8px; border-top:1px solid var(--line); padding-top:5px; color:var(--muted); font-size:8.8px; }}
  @media (max-width: 640px) {{
    .kpis {{ grid-template-columns: 1fr 1fr; }}
    .tablewrap {{ overflow-x:auto; }}
    table {{ min-width: 640px; }}
  }}
  @media print {{ body {{ padding:0; max-width:none; font-size:9.4px; }} .kpi .value {{ font-size:17px; }}
                  td {{ padding:2px 4px; }} footer {{ font-size:8px; }}
                  body {{ line-height:1.3; }} .kpis {{ margin:6px 0; }} .kpi {{ padding:5px 8px; }}
                  h2 {{ margin:6px 0 3px; }} li {{ margin-bottom:1px; }} }}
</style></head>
<body>
<header>
  <div><h1>Cyber risk: board summary</h1>
    <div>{_e(res.org)} <span class="synthetic">SYNTHETIC DATA · DEMO ONLY</span></div></div>
  <div class="meta">Data as of {res.as_of:%d %b %Y}<br>Sources: {src}</div>
</header>

<section class="kpis">
  <div class="kpi"><div class="label">Expected annual loss</div><div class="value">{_e(inr(p['ale_mean']))}</div>
    <div class="sub">80% range {_e(inr(p['ale_p10']))} to {_e(inr(p['ale_p90']))}</div></div>
  <div class="kpi"><div class="label">Work to do</div><div class="value">{h['root_causes']} fixes</div>
    <div class="sub">{res.raw_rows:,} scanner rows → {h['findings']:,} unique findings → {h['root_causes']} root causes</div></div>
  <div class="kpi"><div class="label">Top {TOP_N} fixes close</div>
    <div class="value">{h['top_risk_share']:.0%} of ₹ risk</div>
    <div class="sub">and {h['top_findings_share']:.0%} of all findings</div></div>
  <div class="kpi"><div class="label">CEA fix clock</div><div class="value">{h['cea_overdue']:,} past window</div>
    <div class="sub">open longer than the 1-month (critical, high) or 3-month window that applies from 1 Apr 2027; the top {TOP_N} clear {h['cea_overdue_closed_by_top']:,}</div></div>
</section>

<div class="strip"><span>Triage (CISA SSVC):</span> {ssvc_chips}
  <span>Coverage: {cov['scanned_assets']} assets scanned, {len(cov['unscanned'])} registered but unscanned, {len(cov['unknown'])} found but not in the CMDB</span></div>

<h2>Top {TOP_N} root causes, ranked by rupee risk</h2>
<div class="tablewrap"><table>
  <thead><tr><th>ID</th><th>Root cause and fix</th><th>Type</th><th class="n">Hosts</th><th class="n">Findings</th>
  <th>SSVC</th><th class="n">₹ risk / yr</th><th class="n">Past CEA window</th><th>Who fixes</th></tr></thead>
  <tbody>{''.join(rows)}</tbody>
</table></div>

<h2>What we ask of the board</h2>
<ul>{''.join(f'<li>{a}</li>' for a in asks)}</ul>
{briefing_html(briefing) if briefing else ''}

<footer>
  <b>Every number has a receipt.</b> Each ID above lists its findings, hosts, scanner references (QID or plugin) and
  source-file rows in <code>receipts.json</code>; <code>findings.csv</code> and <code>root_causes.csv</code> hold the
  full detail. Duplicates across Qualys and Tenable are merged ({cov['multi_scanner_findings']} findings seen by both).
  Rupee risk follows FAIR (loss event frequency × loss magnitude) with {p['iterations']:,} Monte Carlo runs; frequency
  uses exploitation state and network zone, magnitude uses each business process's ₹ per hour of downtime from the
  CMDB plus response, data-breach and OT costs. Every assumption is in <code>sutra/risk.py</code> and is a hypothesis,
  not calibrated loss data. SSVC is a simplified deployer tree. CEA windows come from a vendor summary and must be
  checked against the gazette text.
</footer>
</body></html>
"""
    return doc


def write_receipts(res: Result, out: Path) -> None:
    by_id = {f.finding_id: f for f in res.findings}
    receipts = {"as_of": res.as_of.isoformat(), "portfolio": res.portfolio, "assumptions": ASSUMPTIONS,
                "root_causes": []}
    for r in res.root_causes:
        receipts["root_causes"].append({
            "id": r.rc_id, "kind": r.kind, "key": r.key, "title": r.title, "fix": r.fix, "executor": r.executor,
            "ssvc": {"decision": r.ssvc, "exploitation": r.exploitation, "exposure": r.exposure,
                     "human_impact": r.human_impact},
            "risk_inr_per_year": {"mean": round(r.ale_mean), "p10": round(r.ale_p10), "p90": round(r.ale_p90),
                                  "inputs": r.risk_inputs},
            "cea_overdue": r.cea_overdue, "cves": r.cves,
            "hosts": [{"asset_id": a, "hostname": res.assets[a].hostname, "ip": res.assets[a].ip,
                       "image": res.assets[a].image, "image_source": res.assets[a].image_source}
                      for a in r.asset_ids],
            "findings": [{"id": fid, "asset_id": by_id[fid].asset_id, "title": by_id[fid].title,
                          "sources": [s.__dict__ for s in by_id[fid].sources]} for fid in r.finding_ids],
        })
    (out / "receipts.json").write_text(json.dumps(receipts, indent=1), encoding="utf-8")

    with (out / "root_causes.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "kind", "title", "fix", "hosts", "findings", "max_severity", "ssvc", "exploitation",
                    "exposure", "human_impact", "risk_inr_mean", "risk_inr_p10", "risk_inr_p90", "cea_overdue",
                    "is_ot", "cves"])
        for r in res.root_causes:
            w.writerow([r.rc_id, r.kind, r.title, r.fix, len(r.asset_ids), len(r.finding_ids), r.max_severity, r.ssvc,
                        r.exploitation, r.exposure, r.human_impact, round(r.ale_mean), round(r.ale_p10),
                        round(r.ale_p90), r.cea_overdue, int(r.is_ot), " ".join(r.cves)])

    with (out / "findings.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["finding_id", "root_cause_id", "asset_id", "hostname", "ip", "in_cmdb", "kind", "title",
                    "severity", "cvss", "cves", "package", "installed", "fixed", "control", "credential_fp",
                    "first_seen", "scanners", "source_rows"])
        for x in res.findings:
            a = res.assets[x.asset_id]
            w.writerow([x.finding_id, x.root_cause_id, a.asset_id, a.hostname, a.ip, int(a.in_cmdb), x.kind, x.title,
                        x.severity, x.cvss, " ".join(x.cves), x.package, x.installed, x.fixed, x.control,
                        x.credential_fp, x.first_seen, "+".join(x.scanners),
                        "; ".join(f"{s.source_file}:{s.source_row}" for s in x.sources)])


def console_summary(res: Result) -> str:
    h = headline(res)
    lines = [
        f"{res.raw_rows} scanner rows -> {h['findings']} unique findings -> {h['root_causes']} root causes",
        f"Expected annual loss {inr(res.portfolio['ale_mean'])} "
        f"(80% range {inr(res.portfolio['ale_p10'])} to {inr(res.portfolio['ale_p90'])})",
        f"Top {TOP_N} root causes close {h['top_findings_share']:.0%} of findings and {h['top_risk_share']:.0%} of rupee risk",
        "",
    ]
    for r in res.root_causes[:TOP_N]:
        lines.append(f"  {r.rc_id} {r.ssvc:<7} {inr(r.ale_mean):>14}  {len(r.finding_ids):>4} findings  {r.title}")
    return "\n".join(lines)


def write_all(res: Result, out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    board = out / "board_summary.html"
    board.write_text(render_board_html(res), encoding="utf-8")
    write_receipts(res, out)
    return board
