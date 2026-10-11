"""The audit pack: what an auditor or the board needs to check compliance, with proof and citations.

The pack is a plain JSON document. It holds the assessment, every finding's timeline and evidence, the
per-asset risk review, incident reports, recurring obligations, an evidence index and a list of evidence gaps.
A SHA-256 digest over the canonical JSON lets anyone confirm later that the pack was not edited.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .engine import OPEN_STATES, EntityAssessment, evaluate_entity, to_jsonable
from .model import AuditFinding, EntityRecords
from .rulepack import RulePack

PACK_FORMAT = "sutra.compliance.audit_pack/1"


@dataclass(frozen=True)
class EvidenceGap:
    kind: str  # missing_reference | no_fix_evidence | fix_evidence_predates_fix | control_without_evidence |
    #            activity_without_evidence | evidence_after_as_of | no_report_evidence
    ref: str
    message: str


@dataclass(frozen=True)
class AuditPack:
    content: dict[str, Any]
    digest: str

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps({**self.content, "digest": {"algorithm": "sha256", "value": self.digest}},
                          indent=indent, ensure_ascii=False, sort_keys=True)


def _canonical(content: dict[str, Any]) -> bytes:
    return json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_audit_pack(text: str) -> bool:
    """True when the digest in an exported pack matches its content."""
    data = json.loads(text)
    digest = data.pop("digest", None)
    if not isinstance(digest, dict) or digest.get("algorithm") != "sha256":
        return False
    return hashlib.sha256(_canonical(data)).hexdigest() == digest.get("value")


def _evidence_refs(records: EntityRecords) -> dict[str, list[str]]:
    """Every evidence id mentioned anywhere, with the places that mention it."""
    refs: dict[str, list[str]] = {}

    def note(ids: tuple[str, ...], where: str) -> None:
        for e in ids:
            refs.setdefault(e, []).append(where)

    for a in records.audits:
        note(a.report_evidence_ids, f"audit:{a.audit_id}:audit_report")
        note(a.closure_evidence_ids, f"audit:{a.audit_id}:closure_report")
    for f in records.findings:
        note(f.fix_evidence_ids, f"finding:{f.finding_id}:fix")
        for c in f.compensating_controls:
            note(c.evidence_ids, f"finding:{f.finding_id}:control:{c.control_id}")
    for i in records.incidents:
        note(i.report_evidence_ids, f"incident:{i.incident_id}:report")
        note(i.sabotage_evidence_ids, f"incident:{i.incident_id}:sabotage_report")
    for n, r in enumerate(records.activities):
        note(r.evidence_ids, f"activity:{r.activity}:{r.asset_id or 'entity'}:{r.performed_on.isoformat()}:{n}")
    return refs


def _evidence_gaps(records: EntityRecords, assessment: EntityAssessment) -> list[EvidenceGap]:
    known = {e.evidence_id: e for e in records.evidence}
    gaps: list[EvidenceGap] = []
    for eid, where in sorted(_evidence_refs(records).items()):
        if eid not in known:
            gaps.append(EvidenceGap("missing_reference", eid, f"Evidence {eid} is referenced by "
                                    f"{', '.join(where)} but is not on file."))
    for e in sorted(records.evidence, key=lambda e: e.evidence_id):
        if e.captured_at > assessment.as_of:
            gaps.append(EvidenceGap("evidence_after_as_of", e.evidence_id,
                                    f"Evidence {e.evidence_id} is dated after the pack's as-of time."))

    tz = assessment.as_of.tzinfo
    for f in sorted(records.findings, key=lambda f: f.finding_id):
        closed = f.closed_on
        if closed is not None and closed <= assessment.as_of_date:
            present = [known[e] for e in f.fix_evidence_ids if e in known]
            if not present:
                gaps.append(EvidenceGap("no_fix_evidence", f.finding_id,
                                        f"Finding {f.finding_id} is closed with no fix evidence on file."))
            elif all(e.captured_at.astimezone(tz).date() < closed for e in present):
                gaps.append(EvidenceGap("fix_evidence_predates_fix", f.finding_id,
                                        f"All fix evidence for {f.finding_id} was captured before it was closed "
                                        f"on {closed}; it cannot show the fix."))
        for c in f.compensating_controls:
            if c.active_on(assessment.as_of_date) and not any(e in known for e in c.evidence_ids):
                gaps.append(EvidenceGap("control_without_evidence", f"{f.finding_id}:{c.control_id}",
                                        f"Compensating control {c.control_id} on {f.finding_id} has no evidence."))
    for a in sorted(records.audits, key=lambda a: a.audit_id):
        if a.report_submitted_on and a.report_submitted_on <= assessment.as_of_date \
                and not any(e in known for e in a.report_evidence_ids):
            gaps.append(EvidenceGap("no_report_evidence", a.audit_id,
                                    f"No copy of the audit report for {a.audit_id} is on file."))
    for i in sorted(records.incidents, key=lambda i: i.incident_id):
        if i.reported_at and not any(e in known for e in i.report_evidence_ids):
            gaps.append(EvidenceGap("no_report_evidence", i.incident_id,
                                    f"No copy of the incident report for {i.incident_id} is on file."))
    for r in records.activities:
        if r.performed_on <= assessment.as_of_date and not any(e in known for e in r.evidence_ids):
            ref = f"{r.activity}:{r.asset_id or 'entity'}:{r.performed_on.isoformat()}"
            gaps.append(EvidenceGap("activity_without_evidence", ref,
                                    f"No evidence for {r.activity.replace('_', ' ')} on {r.performed_on}."))
    return gaps


def _finding_timeline(f: AuditFinding, report_on: Any, due_on: Any) -> list[dict[str, str]]:
    events = []
    if report_on:
        events.append({"on": report_on.isoformat(), "event": "audit_report_submitted"})
    if due_on:
        events.append({"on": due_on.isoformat(), "event": "fix_due"})
    for c in f.compensating_controls:
        events.append({"on": c.implemented_on.isoformat(), "event": f"compensating_control_in_place:{c.control_id}"})
        if c.withdrawn_on:
            events.append({"on": c.withdrawn_on.isoformat(), "event": f"compensating_control_withdrawn:{c.control_id}"})
    if f.scheduled_fix:
        events.append({"on": f.scheduled_fix.planned_on.isoformat(), "event": "fix_scheduled"})
    if f.fixed_on:
        events.append({"on": f.fixed_on.isoformat(), "event": "fixed"})
    if f.auditor_cleared_on:
        events.append({"on": f.auditor_cleared_on.isoformat(), "event": "auditor_cleared"})
    return sorted(events, key=lambda e: (e["on"], e["event"]))


def build_audit_pack(records: EntityRecords, pack: RulePack, now: datetime,
                     generated_at: datetime | None = None) -> AuditPack:
    """Assess the entity and assemble the audit pack. ``generated_at`` defaults to ``now``."""
    generated_at = generated_at or now
    if generated_at.tzinfo is None:
        raise ValueError("generated_at must be timezone-aware")
    assessment = evaluate_entity(records, pack, now)
    audits_by_id = {a.audit_id: a for a in records.audits}
    findings_by_id = {f.finding_id: f for f in records.findings}
    assessed = {fa.finding_id: fa for aa in assessment.audits for fa in aa.findings}

    audits_out = []
    for aa in assessment.audits:
        audit = audits_by_id[aa.audit_id]
        finding_entries = []
        for fa in aa.findings:
            f = findings_by_id[fa.finding_id]
            finding_entries.append({
                "assessment": to_jsonable(fa),
                "asset_ids": list(f.asset_ids),
                "fix_evidence_ids": list(f.fix_evidence_ids),
                "compensating_controls": to_jsonable(f.compensating_controls),
                "scheduled_fix": to_jsonable(f.scheduled_fix),
                "auditor_cleared_on": f.auditor_cleared_on.isoformat() if f.auditor_cleared_on else None,
                "carried_from_finding_id": f.carried_from_finding_id,
                "timeline": _finding_timeline(f, audit.report_submitted_on, fa.due_on),
            })
        audits_out.append({
            "audit_id": audit.audit_id, "auditor": audit.auditor, "auditor_status": audit.auditor_status,
            "auditor_eligible": aa.auditor_eligible,
            "eligibility_citation": to_jsonable(aa.eligibility_citation),
            "started_on": audit.started_on.isoformat(),
            "report_submitted_on": audit.report_submitted_on.isoformat() if audit.report_submitted_on else None,
            "closure_report_on": audit.closure_report_on.isoformat() if audit.closure_report_on else None,
            "report_evidence_ids": list(audit.report_evidence_ids),
            "closure_evidence_ids": list(audit.closure_evidence_ids),
            "deliverables": to_jsonable(aa.deliverables),
            "findings": finding_entries,
        })

    # Per-asset risk review, for the six-monthly risk assessment and to show open findings per asset.
    risk_reviews = {p.asset_id: p for p in assessment.periodic if p.activity == "asset_risk_assessment"}
    assets_out = []
    for asset in sorted(records.assets, key=lambda a: a.asset_id):
        open_findings = sorted(fid for fid, fa in assessed.items()
                               if asset.asset_id in findings_by_id[fid].asset_ids and fa.state in OPEN_STATES)
        review = risk_reviews.get(asset.asset_id)
        last_records = [r for r in records.activities if r.activity == "asset_risk_assessment"
                        and r.asset_id == asset.asset_id and r.performed_on <= assessment.as_of_date]
        latest = max(last_records, key=lambda r: r.performed_on, default=None)
        assets_out.append({
            "asset_id": asset.asset_id, "name": asset.name, "critical": asset.critical,
            "risk_assessment": to_jsonable(review) if review else None,
            "risk_assessment_evidence_ids": list(latest.evidence_ids) if latest else [],
            "open_finding_ids": open_findings,
        })

    refs = _evidence_refs(records)
    evidence_out = [{**to_jsonable(e), "referenced_by": sorted(refs.get(e.evidence_id, []))}
                    for e in sorted(records.evidence, key=lambda e: e.evidence_id)]
    gaps = _evidence_gaps(records, assessment)

    content = {
        "format": PACK_FORMAT,
        "generated_at": generated_at.isoformat(),
        "as_of": now.isoformat(),
        "entity": to_jsonable(records.entity),
        "rule_pack": {**pack.summary(), "sources": [to_jsonable(s) for s in pack.sources.values()],
                      "deferred": to_jsonable(pack.deferred)},
        "summary": {
            "status": assessment.status.value,
            "status_if_in_force": assessment.status_if_in_force.value,
            "regulation_in_force": assessment.regulation_in_force,
            "applicability": to_jsonable(assessment.applicability),
            "finding_counts": assessment.finding_counts,
            "issues": to_jsonable(assessment.issues),
            "upcoming_deadlines": to_jsonable(assessment.upcoming_deadlines),
            "unchecked": list(assessment.unchecked),
            "evidence_gap_count": len(gaps),
        },
        "audits": audits_out,
        "audit_cycle": to_jsonable(assessment.audit_cycle),
        "prior_findings": to_jsonable(assessment.prior_findings),
        "incidents": to_jsonable(assessment.incidents),
        "recurring_obligations": to_jsonable(assessment.periodic),
        "assets": assets_out,
        "evidence": evidence_out,
        "evidence_gaps": to_jsonable(gaps),
    }
    content = json.loads(_canonical(content))  # normalise to exactly what is exported
    return AuditPack(content=content, digest=hashlib.sha256(_canonical(content)).hexdigest())


__all__ = ["AuditPack", "EvidenceGap", "PACK_FORMAT", "build_audit_pack", "verify_audit_pack"]
