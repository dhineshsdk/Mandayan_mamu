"""Explanations written by fixed rules from the same facts. They need no model and pass the same checks."""

from __future__ import annotations

from .grounding import Claim
from .nodes import FactSet, Node
from .schema import BRIEFING_SECTIONS

KIND_PHRASE = {
    "base-image": "one golden image that was built with the flaw", "package": "one package present on many machines",
    "config-template": "one configuration template applied to many machines",
    "shared-credential": "one credential shared across machines", "fleet-config": "one setting across the fleet",
    "fleet": "one cause across the fleet", "single": "a single machine",
}
KIND_FIX = {
    "base-image": "Rebuilding the image fixes every machine built from it",
    "package": "Updating the package fixes it wherever it is installed",
    "config-template": "Correcting the template fixes every machine that uses it",
    "shared-credential": "Rotating the credential fixes every place it is used",
    "fleet-config": "Changing the setting centrally fixes it everywhere",
    "fleet": "One coordinated change fixes it across the fleet",
    "single": "Fixing this one machine closes it",
}
EXPLOIT_PHRASE = {"active": "is being exploited in the wild", "poc": "has public proof-of-concept exploit code",
                  "none": "has no known exploitation"}
EXPOSURE_PHRASE = {"open": "reachable from the internet", "controlled": "inside the corporate network or a DMZ",
                   "small": "on a segmented network"}


def _n(node: Node, key: str):
    return node.fields.get(key)


def root_cause_claims(facts: FactSet) -> list[Claim]:
    r = facts.nodes["R1"]
    f = r.fields
    claims = [
        Claim(f"{{R1}} is {KIND_PHRASE[f['kind']]}: {f['findings']} findings on {f['hosts']} hosts. "
              f"{KIND_FIX[f['kind']]}.", ("R1",), "supports"),
        Claim(f"It is rated {f['ssvc']} because the weakness {EXPLOIT_PHRASE[f['exploitation']]} and the machines "
              f"are {EXPOSURE_PHRASE[f['exposure']]}; the impact on people and operations is {f['human_impact']}.",
              ("R1",), "supports"),
        Claim(f"Expected yearly loss is {f['ale_label']} ({f['range_percent']}% range {f['ale_p10_label']} to "
              f"{f['ale_p90_label']}).", ("R1",), "supports"),
    ]
    if f["cea_overdue"]:
        due = f" The earliest due date was {f['earliest_due']}." if "earliest_due" in f else ""
        claims.append(Claim(f"{f['cea_overdue']} findings are past the CEA fix deadline.{due}", ("R1",), "supports"))
    else:
        claims.append(Claim("No finding in this root cause is past the CEA fix deadline.", ("R1",), "contradicts"))
    if f["is_ot"]:
        claims.append(Claim("It touches plant systems, so the fix is a staged plan carried out by a plant engineer "
                            "with OEM approval, not an automatic change.", ("R1",), "next_check", "stage_change"))
    if f["hosts_shown"] < f["hosts_total"]:
        claims.append(Claim(f"Only {f['hosts_shown']} of {f['hosts_total']} hosts are itemised here; the rest follow "
                            f"the same cause.",
                            ("R1",), "uncertainty"))
    hostless = [ref for ref in facts.refs("asset") if not facts.nodes[ref].fields["in_cmdb"]]
    if hostless:
        claims.append(Claim(f"{{{hostless[0]}}} is not in the CMDB, so its owner and importance are unconfirmed.",
                            (hostless[0],), "uncertainty", "open_ticket"))
    if f.get("injection_suspects"):
        claims.append(Claim(f"{f['injection_suspects']} findings here contain text addressed to an AI model; Sutra "
                            f"did not act on it, and the machines stay in scope.", ("R1",), "uncertainty",
                            "notify"))
    return claims


def briefing_claims(facts: FactSet) -> dict[str, list[Claim]]:
    b = facts.nodes["B1"].fields
    k = facts.nodes["K1"].fields
    out: dict[str, list[Claim]] = {key: [] for key in BRIEFING_SECTIONS}
    out["headline"] = [
        Claim(f"Expected yearly loss from open vulnerabilities is {b['ale_label']} ({b['range_percent']}% range "
              f"{b['ale_p10_label']} to {b['ale_p90_label']}).", ("B1",), "supports"),
        Claim(f"{b['findings']} findings reduce to {b['root_causes']} root causes; the top {b['top_n']} account for "
              f"{b['top_risk_share']}% of the risk and {b['top_findings_share']}% of the findings.", ("B1",),
              "supports"),
    ]
    tops = [ref for ref in facts.refs("root_cause")]
    for ref in tops:
        f = facts.nodes[ref].fields
        out["top_risks"].append(Claim(
            f"{{{ref}}} ({f['ssvc']}) carries {f['ale_label']} a year across {f['hosts']} hosts.", (ref,),
            "supports", "open_ticket" if f["ssvc"] in ("Act", "Attend") and not f["is_ot"] else "none"))
    if not tops:
        out["top_risks"].append(Claim("There are no open root causes to report.", ("B1",), "supports"))
    cov = [Claim(f"{k['scanned_assets']} of {k['cmdb_assets']} assets in the CMDB have been scanned.", ("K1",),
                 "supports")]
    if k["unscanned"]:
        cov.append(Claim(f"{k['unscanned']} assets have never been scanned, so any risk on them is unmeasured.",
                         ("K1",), "uncertainty", "request_rescan"))
    if k["unknown"]:
        cov.append(Claim(f"{k['unknown']} assets were found by scanners but are not in the CMDB.", ("K1",),
                         "uncertainty"))
    if k.get("unowned"):
        cov.append(Claim(f"{k['unowned']} assets have no owning team, so nobody will be asked to fix them.", ("K1",),
                         "uncertainty", "notify"))
    out["coverage"] = cov
    if b["cea_overdue"]:
        out["compliance_clock"] = [Claim(
            f"{b['cea_overdue']} findings are past the CEA fix deadline; fixing the top {b['top_n']} root causes "
            f"closes {b['cea_overdue_closed_by_top']} of them.", ("B1",), "supports")]
    else:
        out["compliance_clock"] = [Claim("No finding is past the CEA fix deadline.", ("B1",), "contradicts")]
    ask = [Claim(f"{b['ssvc_act']} root causes are rated Act and {b['ssvc_attend']} Attend; these need an owner "
                 f"and a date.", ("B1",), "next_check")]
    out["decisions"] = ask
    return out
