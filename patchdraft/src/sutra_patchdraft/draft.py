"""The finished draft: a validated raw draft with every ref replaced by the real host, finding or change."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from .facts import ROOT_CAUSE_REF, Facts
from .inputs import DraftInput
from .schema import IT_VERBS, OT_TOOL, OT_VERBS
from .windows import SHUTDOWN_NOT_SET, it_windows, ot_window


@dataclass
class Citation:
    ref: str
    kind: str  # root-cause | host | finding | change
    id: str  # rc_id, asset_id, finding_id or the change ref
    label: str


@dataclass
class Ring:
    number: int
    name: str
    purpose: str
    hosts: list[str]  # hostnames
    asset_ids: list[str]
    window: str


@dataclass
class Step:
    number: int
    action: str
    label: str
    ring: int  # 0 = before or across all rings
    changes: list[str]
    detail: str
    cites: list[Citation]


@dataclass
class PatchJobDraft:
    rc_id: str
    lane: str  # "it": runs through a patch tool after approval; "ot": staged plan carried out by a plant engineer
    source: str  # "ai" or "template"
    summary: str
    tool: str
    executable: bool
    targets: list[str]
    target_asset_ids: list[str]
    excluded: list[dict]
    changes: list[dict]
    rings: list[Ring]
    steps: list[Step]
    prechecks: list[dict]
    rollback: dict
    window: str
    assumptions: list[str]
    oem_approval: str | None = None
    oem_request: dict | None = None
    compensating_controls: list[dict] = field(default_factory=list)
    model: str | None = None
    attempts: int = 0
    fallback_reason: str | None = None
    warnings: list[str] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict:
        return asdict(self)

    def playbook_text(self) -> str:
        lines = []
        for s in self.steps:
            where = f" (ring {s.ring})" if s.ring else ""
            what = f" [{'; '.join(s.changes)}]" if s.changes else ""
            lines.append(f"{s.number}. {s.label}{where}{what}: {s.detail}")
        return "\n".join(lines)

    def to_legacy_dict(self) -> dict:
        """The draft in the shape the current app's patch-job screen reads (``sutra.patch.draft_job``)."""
        d = {
            "targets": self.targets, "window": self.window,
            "rings": [{"name": r.name, "hosts": r.hosts} for r in self.rings],
            "changes": [c["text"] for c in self.changes], "tool": self.tool, "summary": self.summary,
            "playbook": self.playbook_text(), "prechecks": [p["text"] for p in self.prechecks],
            "rollback": " ".join([self.rollback["trigger"], *self.rollback["steps"]]).strip(),
            "source": self.source,
        }
        if self.lane == "ot":
            d["oem_approval"] = self.oem_approval
            d["compensating_control"] = "; ".join(c["control"] for c in self.compensating_controls)
        return d


def _citation(ref: str, facts: Facts, inp: DraftInput) -> Citation:
    if ref == ROOT_CAUSE_REF:
        return Citation(ref, "root-cause", inp.root_cause.rc_id, inp.root_cause.title)
    if ref in facts.hosts:
        h = facts.hosts[ref]
        return Citation(ref, "host", h.asset_id, h.hostname or h.asset_id)
    if ref in facts.findings:
        f = facts.findings[ref]
        where = f" ({', '.join(f.scanner_refs)})" if f.scanner_refs else ""
        return Citation(ref, "finding", f.finding_id, f"{f.title}{where}")
    c = facts.changes[ref]
    return Citation(ref, "change", ref, c.text)


def _hostnames(refs: list[str], facts: Facts) -> list[str]:
    return [facts.hosts[r].hostname or facts.hosts[r].asset_id for r in refs]


def render(raw: dict, lane: str, facts: Facts, inp: DraftInput, *, source: str, model: str | None = None,
           attempts: int = 0, fallback_reason: str | None = None, warnings: list[str] | None = None
           ) -> PatchJobDraft:
    """Turn a raw draft that passed ``grounding.validate`` into a PatchJobDraft."""
    def cite(refs: list[str]) -> list[Citation]:
        return [_citation(r, facts, inp) for r in dict.fromkeys(refs)]

    assumptions = list(raw["assumptions"])
    if lane == "it":
        windows = it_windows(inp.policy, inp.as_of, len(raw["rings"]))
    else:
        shutdown = ot_window(inp.policy, inp.as_of)
        windows = [shutdown or SHUTDOWN_NOT_SET] * len(raw["rings"])
        if shutdown is None:
            assumptions.append("No planned shutdown date was provided; operations must name the slot before "
                               "the plan can be scheduled.")
    rings = [Ring(number=i, name=r["name"].strip(), purpose=r["purpose"].strip(), hosts=_hostnames(r["hosts"], facts),
                  asset_ids=[facts.hosts[h].asset_id for h in r["hosts"]], window=windows[i - 1])
             for i, r in enumerate(raw["rings"], 1)]
    verbs = IT_VERBS if lane == "it" else OT_VERBS
    steps = [Step(number=i, action=s["action"], label=verbs[s["action"]], ring=s["ring"],
                  changes=[facts.changes[c].text for c in s["changes"]], detail=s["detail"].strip(),
                  cites=cite(s["cites"] + s["changes"]))
             for i, s in enumerate(raw["steps"], 1)]
    placed = [h for r in raw["rings"] for h in r["hosts"]]
    excluded_refs = {e["host"] for e in raw["excluded_hosts"]}
    draft = PatchJobDraft(
        rc_id=inp.root_cause.rc_id, lane=lane, source=source, summary=raw["summary"].strip(),
        tool=raw["tool"] if lane == "it" else OT_TOOL, executable=lane == "it",
        targets=_hostnames(placed, facts), target_asset_ids=[facts.hosts[h].asset_id for h in placed],
        excluded=[{"hostname": facts.hosts[e["host"]].hostname, "asset_id": facts.hosts[e["host"]].asset_id,
                   "reason": e["reason"].strip()} for e in raw["excluded_hosts"]],
        changes=[{"ref": c.ref, "text": c.text,
                  "hosts": _hostnames([h for h in c.host_refs if h not in excluded_refs], facts),
                  "finding_ids": [facts.findings[f].finding_id for f in c.finding_refs]}
                 for c in facts.changes.values()],
        rings=rings, steps=steps,
        prechecks=[{"text": p["text"].strip(), "cites": cite(p["cites"])} for p in raw["prechecks"]],
        rollback={"trigger": raw["rollback"]["trigger"].strip(), "steps": [s.strip() for s in raw["rollback"]["steps"]],
                  "cites": cite(raw["rollback"]["cites"])},
        window=windows[0], assumptions=assumptions, model=model, attempts=attempts,
        fallback_reason=fallback_reason, warnings=list(warnings or []),
    )
    if lane == "ot":
        oem = raw["oem_approval_request"]
        draft.oem_approval = "Pending"
        draft.oem_request = {"changes": [facts.changes[c].text for c in oem["changes"]],
                             "detail": oem["detail"].strip(), "cites": cite(oem["cites"] + oem["changes"])}
        draft.compensating_controls = [{"control": c["control"].strip(), "hosts": _hostnames(c["hosts"], facts),
                                        "cites": cite(c["cites"])} for c in raw["compensating_controls"]]
    return draft
