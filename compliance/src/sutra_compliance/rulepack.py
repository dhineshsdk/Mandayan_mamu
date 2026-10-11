"""Load and validate a rule pack: regulation obligations stored as data, each one citing its sources.

The pack is a TOML file (see ``rules/cea_cs_2026.toml``). Loading checks the whole file and reports every problem
at once, so a correction that breaks something fails loudly instead of silently changing a deadline.
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, timedelta, timezone
from importlib import resources
from pathlib import Path
from typing import Any

from .durations import Duration

VERIFICATION_STATES = ("unverified_against_gazette", "verified_against_gazette")
CONFIDENCE_LEVELS = ("corroborated", "single_source", "conflicting")
SOURCE_KINDS = ("official", "secondary", "internal_research")
SEVERITIES = ("critical", "high", "medium", "low")
ENTITY_TYPES = (
    "generator", "captive_plant", "energy_storage",
    "transmission_licensee", "distribution_licensee", "nldc", "rldc", "sldc",
    "power_exchange", "otc_platform", "vendor",
)
DELIVERABLES = ("audit_report", "closure_report")
AUDITOR_STATUSES = ("cert_in_empanelled", "mop_designated")
INCIDENT_TRIGGERS = ("incident_detected", "sabotage_concluded")
RECIPIENTS = ("csirt_power", "cert_in")
COMPENSATING_TRIGGERS = ("after_fix_deadline", "while_open")
PERIODIC_SCOPES = ("entity", "asset", "critical_asset")

DEFAULT_PACK = "cea_cs_2026.toml"


class RulePackError(ValueError):
    """The rule pack is malformed. ``problems`` lists every issue found."""

    def __init__(self, problems: list[str]):
        self.problems = list(problems)
        super().__init__("invalid rule pack:\n  - " + "\n  - ".join(self.problems))


@dataclass(frozen=True)
class Source:
    id: str
    title: str
    url: str
    kind: str
    read: bool


@dataclass(frozen=True, kw_only=True)
class Rule:
    id: str
    kind: str
    topic: str
    title: str
    summary: str
    sources: tuple[str, ...]
    confidence: str
    verification: str
    gazette_clause: str = ""
    notes: str = ""
    enabled: bool = True


@dataclass(frozen=True, kw_only=True)
class AuditIntervalRule(Rule):
    every_financial_year: bool
    min_gap: Duration | None
    max_gap: Duration | None


@dataclass(frozen=True, kw_only=True)
class AuditorEligibilityRule(Rule):
    allowed: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class AuditDeliverableRule(Rule):
    deliverable: str
    anchor: str
    duration: Duration
    expects_evidence: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class FixDeadlineRule(Rule):
    severities: tuple[str, ...]
    anchor: str
    duration: Duration


@dataclass(frozen=True, kw_only=True)
class CompensatingControlRule(Rule):
    severities: tuple[str, ...]
    trigger: str


@dataclass(frozen=True, kw_only=True)
class PriorFindingsRule(Rule):
    pass


@dataclass(frozen=True, kw_only=True)
class AuditorRotationRule(Rule):
    max_consecutive: int
    variants: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class IncidentReportRule(Rule):
    trigger: str
    duration: Duration
    recipients: tuple[str, ...]
    expects_evidence: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class PeriodicRule(Rule):
    activity: str
    scope: str
    interval: Duration


@dataclass(frozen=True)
class ChangeCategory:
    id: str
    label: str


@dataclass(frozen=True, kw_only=True)
class ChangePreAuditRule(Rule):
    categories: tuple[ChangeCategory, ...]


@dataclass(frozen=True)
class ApplicabilityRule:
    id: str
    entity_types: tuple[str, ...]
    min_capacity_mw: float | None
    excluded_topics: tuple[str, ...]
    chapters_determined: bool
    sources: tuple[str, ...]
    confidence: str
    verification: str
    gazette_clause: str
    notes: str


@dataclass(frozen=True)
class DeferredObligations:
    clauses: tuple[str, ...]
    topics: tuple[str, ...]
    sources: tuple[str, ...]
    confidence: str
    verification: str
    notes: str


@dataclass(frozen=True)
class Citation:
    """What a computed result rests on: the rule, the pack version and the sources behind the rule."""

    rule_id: str
    pack_id: str
    pack_version: str
    verification: str
    confidence: str
    gazette_clause: str
    sources: tuple[Source, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "pack_id": self.pack_id,
            "pack_version": self.pack_version,
            "verification": self.verification,
            "confidence": self.confidence,
            "gazette_clause": self.gazette_clause or None,
            "sources": [{"id": s.id, "title": s.title, "url": s.url, "kind": s.kind} for s in self.sources],
        }


@dataclass(frozen=True)
class RulePack:
    id: str
    title: str
    version: str
    jurisdiction: str
    notification: str
    enabling_provision: str
    in_force_from: date
    utc_offset_minutes: int
    financial_year_start_month: int
    verification: str
    verification_note: str
    metadata_sources: tuple[str, ...]
    sources: Mapping[str, Source]
    rules: tuple[Rule, ...]
    applicability: tuple[ApplicabilityRule, ...]
    deferred: tuple[DeferredObligations, ...]
    _by_id: Mapping[str, Rule] = field(default_factory=dict, repr=False, compare=False)

    @property
    def local_tz(self) -> timezone:
        return timezone(timedelta(minutes=self.utc_offset_minutes))

    def rule(self, rule_id: str) -> Rule:
        return self._by_id[rule_id]

    def rules_of(self, cls: type[Rule], *, include_disabled: bool = False) -> list[Any]:
        return [r for r in self.rules if isinstance(r, cls) and (include_disabled or r.enabled)]

    def fix_rule_for(self, severity: str) -> FixDeadlineRule | None:
        for rule in self.rules_of(FixDeadlineRule):
            if severity in rule.severities:
                return rule
        return None

    def compensating_rule_for(self, severity: str) -> CompensatingControlRule | None:
        for rule in self.rules_of(CompensatingControlRule):
            if severity in rule.severities:
                return rule
        return None

    def cite(self, rule: Rule | ApplicabilityRule) -> Citation:
        return Citation(
            rule_id=rule.id,
            pack_id=self.id,
            pack_version=self.version,
            verification=rule.verification,
            confidence=rule.confidence,
            gazette_clause=rule.gazette_clause,
            sources=tuple(self.sources[s] for s in rule.sources),
        )

    def is_in_force(self, on: date) -> bool:
        return on >= self.in_force_from

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "version": self.version,
            "notification": self.notification,
            "in_force_from": self.in_force_from.isoformat(),
            "verification": self.verification,
            "verification_note": self.verification_note,
            "unverified_rules": sorted(r.id for r in self.rules if r.verification != "verified_against_gazette"),
            "disabled_rules": sorted(r.id for r in self.rules if not r.enabled),
        }


# --------------------------------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------------------------------


def load_rule_pack(path: str | Path | None = None) -> RulePack:
    """Load a rule pack. With no path, loads the bundled CEA 2026 pack."""
    if path is None:
        raw_text = resources.files("sutra_compliance.rules").joinpath(DEFAULT_PACK).read_text(encoding="utf-8")
    else:
        raw_text = Path(path).read_text(encoding="utf-8")
    try:
        data = tomllib.loads(raw_text)
    except tomllib.TOMLDecodeError as exc:
        raise RulePackError([f"not valid TOML: {exc}"]) from exc
    return parse_rule_pack(data)


class _Reader:
    """Pulls typed fields out of one TOML table, recording problems instead of stopping at the first."""

    def __init__(self, table: Mapping[str, Any], where: str, problems: list[str]):
        self.table = table
        self.where = where
        self.problems = problems
        self.used: set[str] = set()

    def _missing(self, key: str) -> None:
        self.problems.append(f"{self.where}: missing '{key}'")

    def get(self, key: str, typ: type | tuple[type, ...], default: Any = ..., *, nonempty: bool = False) -> Any:
        self.used.add(key)
        if key not in self.table:
            if default is ...:
                self._missing(key)
                return None
            return default
        value = self.table[key]
        if not isinstance(value, typ) or (typ is int and isinstance(value, bool)):
            self.problems.append(f"{self.where}: '{key}' has the wrong type ({type(value).__name__})")
            return None if default is ... else default
        if nonempty and not value:
            self.problems.append(f"{self.where}: '{key}' must not be empty")
        return value

    def choice(self, key: str, allowed: tuple[str, ...], default: Any = ...) -> Any:
        value = self.get(key, str, default)
        if value is not None and value is not default and value not in allowed:
            self.problems.append(f"{self.where}: '{key}' is {value!r}; expected one of {', '.join(allowed)}")
        return value

    def str_list(self, key: str, allowed: tuple[str, ...] | None = None, default: Any = ...,
                 *, nonempty: bool = False) -> tuple[str, ...]:
        value = self.get(key, list, default, nonempty=nonempty)
        if value is None:
            return ()
        out = []
        for item in value:
            if not isinstance(item, str):
                self.problems.append(f"{self.where}: '{key}' must contain strings only")
                continue
            if allowed is not None and item not in allowed:
                self.problems.append(f"{self.where}: '{key}' has {item!r}; expected one of {', '.join(allowed)}")
            out.append(item)
        if len(set(out)) != len(out):
            self.problems.append(f"{self.where}: '{key}' has duplicates")
        return tuple(out)

    def duration(self, key: str, *, optional: bool = False) -> Duration | None:
        raw = self.get(key, dict, None if optional else ...)
        if raw is None:
            return None
        try:
            return Duration.from_mapping(raw)
        except ValueError as exc:
            self.problems.append(f"{self.where}: '{key}': {exc}")
            return None

    def finish(self) -> None:
        extra = set(self.table) - self.used
        if extra:
            self.problems.append(f"{self.where}: unknown key(s) {sorted(extra)}")


def _common(r: _Reader, source_ids: set[str]) -> dict[str, Any]:
    fields = {
        "id": r.get("id", str, nonempty=True),
        "kind": r.get("kind", str),
        "topic": r.get("topic", str, nonempty=True),
        "title": r.get("title", str, nonempty=True),
        "summary": r.get("summary", str, nonempty=True),
        "sources": r.str_list("sources", nonempty=True),
        "confidence": r.choice("confidence", CONFIDENCE_LEVELS),
        "verification": r.choice("verification", VERIFICATION_STATES),
        "gazette_clause": r.get("gazette_clause", str, ""),
        "notes": (r.get("notes", str, "") or "").strip(),
        "enabled": r.get("enabled", bool, True),
    }
    _check_citation(r, fields["sources"], fields["verification"], fields["gazette_clause"], source_ids)
    return fields


def _check_citation(r: _Reader, sources: tuple[str, ...], verification: str | None, clause: str | None,
                    source_ids: set[str]) -> None:
    for s in sources:
        if s not in source_ids:
            r.problems.append(f"{r.where}: cites unknown source {s!r}")
    if verification == "verified_against_gazette":
        if not clause:
            r.problems.append(f"{r.where}: verified_against_gazette needs gazette_clause")
        if "cea-gazette" not in sources:
            r.problems.append(f"{r.where}: verified_against_gazette must cite 'cea-gazette'")


def _parse_rule(table: Mapping[str, Any], index: int, problems: list[str], source_ids: set[str]) -> Rule | None:
    where = f"rules[{index}] ({table.get('id', '?')})"
    r = _Reader(table, where, problems)
    common = _common(r, source_ids)
    kind = common["kind"]
    rule: Rule | None
    if kind == "audit_interval":
        rule = AuditIntervalRule(**common, every_financial_year=r.get("every_financial_year", bool),
                                 min_gap=r.duration("min_gap", optional=True),
                                 max_gap=r.duration("max_gap", optional=True))
    elif kind == "auditor_eligibility":
        rule = AuditorEligibilityRule(**common, allowed=r.str_list("allowed", AUDITOR_STATUSES, nonempty=True))
    elif kind == "audit_deliverable":
        rule = AuditDeliverableRule(**common, deliverable=r.choice("deliverable", DELIVERABLES),
                                    anchor=r.choice("anchor", ("audit_started",)), duration=r.duration("duration"),
                                    expects_evidence=r.str_list("expects_evidence", default=[]))
    elif kind == "finding_fix_deadline":
        rule = FixDeadlineRule(**common, severities=r.str_list("severities", SEVERITIES, nonempty=True),
                               anchor=r.choice("anchor", ("audit_report_submitted",)),
                               duration=r.duration("duration"))
    elif kind == "compensating_control":
        rule = CompensatingControlRule(**common, severities=r.str_list("severities", SEVERITIES, nonempty=True),
                                       trigger=r.choice("trigger", COMPENSATING_TRIGGERS))
    elif kind == "prior_findings_check":
        rule = PriorFindingsRule(**common)
    elif kind == "auditor_rotation":
        rule = AuditorRotationRule(**common, max_consecutive=r.get("max_consecutive", int),
                                   variants=r.str_list("variants", default=[]))
        if rule.enabled and not (rule.max_consecutive or 0) > 0:
            problems.append(f"{where}: an enabled auditor_rotation rule needs max_consecutive > 0")
    elif kind == "incident_report":
        rule = IncidentReportRule(**common, trigger=r.choice("trigger", INCIDENT_TRIGGERS),
                                  duration=r.duration("duration"),
                                  recipients=r.str_list("recipients", RECIPIENTS),
                                  expects_evidence=r.str_list("expects_evidence", default=[]))
    elif kind == "periodic":
        rule = PeriodicRule(**common, activity=r.get("activity", str, nonempty=True),
                            scope=r.choice("scope", PERIODIC_SCOPES), interval=r.duration("interval"))
    elif kind == "change_pre_audit":
        cats = []
        for i, c in enumerate(r.get("categories", list, nonempty=True) or []):
            if not isinstance(c, dict) or set(c) != {"id", "label"} or not all(isinstance(v, str) and v
                                                                                for v in c.values()):
                problems.append(f"{where}: categories[{i}] must be {{ id = \"...\", label = \"...\" }}")
                continue
            cats.append(ChangeCategory(c["id"], c["label"]))
        if len({c.id for c in cats}) != len(cats):
            problems.append(f"{where}: duplicate category ids")
        rule = ChangePreAuditRule(**common, categories=tuple(cats))
    else:
        problems.append(f"{where}: unknown kind {kind!r}")
        return None
    r.finish()
    return rule


def parse_rule_pack(data: Mapping[str, Any]) -> RulePack:
    problems: list[str] = []

    unknown_top = set(data) - {"pack", "sources", "rules", "applicability", "deferred"}
    if unknown_top:
        problems.append(f"unknown top-level table(s) {sorted(unknown_top)}")

    sources: dict[str, Source] = {}
    for i, s in enumerate(data.get("sources", [])):
        r = _Reader(s, f"sources[{i}]", problems)
        src = Source(id=r.get("id", str, nonempty=True), title=r.get("title", str, nonempty=True),
                     url=r.get("url", str, nonempty=True), kind=r.choice("kind", SOURCE_KINDS),
                     read=r.get("read", bool))
        r.finish()
        if src.id in sources:
            problems.append(f"sources[{i}]: duplicate source id {src.id!r}")
        if src.id:
            sources[src.id] = src
    source_ids = set(sources)
    if not sources:
        problems.append("no [[sources]] defined")

    p = _Reader(data.get("pack", {}), "[pack]", problems)
    meta = {
        "id": p.get("id", str, nonempty=True),
        "title": p.get("title", str, nonempty=True),
        "version": p.get("version", str, nonempty=True),
        "jurisdiction": p.get("jurisdiction", str, nonempty=True),
        "notification": p.get("notification", str, nonempty=True),
        "enabling_provision": p.get("enabling_provision", str, nonempty=True),
        "in_force_from": p.get("in_force_from", date),
        "utc_offset_minutes": p.get("utc_offset_minutes", int),
        "financial_year_start_month": p.get("financial_year_start_month", int),
        "verification": p.choice("verification", VERIFICATION_STATES),
        "verification_note": (p.get("verification_note", str, "") or "").strip(),
        "metadata_sources": p.str_list("metadata_sources", nonempty=True),
    }
    p.finish()
    for s in meta["metadata_sources"]:
        if s not in source_ids:
            problems.append(f"[pack]: metadata_sources cites unknown source {s!r}")
    fy = meta["financial_year_start_month"]
    if fy is not None and not 1 <= fy <= 12:
        problems.append("[pack]: financial_year_start_month must be 1-12")
    offset = meta["utc_offset_minutes"]
    if offset is not None and not -24 * 60 < offset < 24 * 60:
        problems.append("[pack]: utc_offset_minutes is out of range")

    rules: list[Rule] = []
    for i, table in enumerate(data.get("rules", [])):
        rule = _parse_rule(table, i, problems, source_ids)
        if rule is not None:
            rules.append(rule)
    by_id: dict[str, Rule] = {}
    for rule in rules:
        if rule.id in by_id:
            problems.append(f"duplicate rule id {rule.id!r}")
        by_id[rule.id] = rule

    if meta["verification"] == "verified_against_gazette":
        unverified = [r.id for r in rules if r.verification != "verified_against_gazette"]
        if unverified:
            problems.append(f"[pack]: marked verified but these rules are not: {', '.join(unverified)}")

    # One enabled rule at most per severity and kind, or a finding's deadline would be ambiguous.
    for cls in (FixDeadlineRule, CompensatingControlRule):
        seen: dict[str, str] = {}
        for rule in rules:
            if isinstance(rule, cls) and rule.enabled:
                for sev in rule.severities:
                    if sev in seen:
                        problems.append(f"severity {sev!r} is covered by both {seen[sev]} and {rule.id}")
                    seen[sev] = rule.id
    deliverables: dict[str, str] = {}
    for rule in rules:
        if isinstance(rule, AuditDeliverableRule) and rule.enabled:
            if rule.deliverable in deliverables:
                problems.append(f"deliverable {rule.deliverable!r} is set by both "
                                f"{deliverables[rule.deliverable]} and {rule.id}")
            deliverables[rule.deliverable] = rule.id
    periodic_seen: dict[str, str] = {}
    for rule in rules:
        if isinstance(rule, PeriodicRule) and rule.enabled:
            if rule.activity in periodic_seen:
                problems.append(f"activity {rule.activity!r} is set by both {periodic_seen[rule.activity]} "
                                f"and {rule.id}")
            periodic_seen[rule.activity] = rule.id
    for rule in rules:
        if isinstance(rule, IncidentReportRule) and rule.duration is not None and not rule.duration.has_time \
                and rule.duration.months:
            problems.append(f"{rule.id}: incident windows must be in weeks, days or hours")

    applicability: list[ApplicabilityRule] = []
    typed: dict[str, str] = {}
    for i, table in enumerate(data.get("applicability", [])):
        r = _Reader(table, f"applicability[{i}] ({table.get('id', '?')})", problems)
        mw = r.get("min_capacity_mw", (int, float), None)
        a = ApplicabilityRule(
            id=r.get("id", str, nonempty=True),
            entity_types=r.str_list("entity_types", ENTITY_TYPES, nonempty=True),
            min_capacity_mw=float(mw) if mw is not None else None,
            excluded_topics=r.str_list("excluded_topics", default=[]),
            chapters_determined=r.get("chapters_determined", bool, True),
            sources=r.str_list("sources", nonempty=True),
            confidence=r.choice("confidence", CONFIDENCE_LEVELS),
            verification=r.choice("verification", VERIFICATION_STATES),
            gazette_clause=r.get("gazette_clause", str, ""),
            notes=(r.get("notes", str, "") or "").strip(),
        )
        _check_citation(r, a.sources, a.verification, a.gazette_clause, source_ids)
        r.finish()
        for t in a.entity_types:
            if t in typed:
                problems.append(f"entity type {t!r} appears in both {typed[t]} and {a.id}")
            typed[t] = a.id
        applicability.append(a)

    deferred: list[DeferredObligations] = []
    for i, table in enumerate(data.get("deferred", [])):
        r = _Reader(table, f"deferred[{i}]", problems)
        d = DeferredObligations(
            clauses=r.str_list("clauses", nonempty=True), topics=r.str_list("topics", nonempty=True),
            sources=r.str_list("sources", nonempty=True), confidence=r.choice("confidence", CONFIDENCE_LEVELS),
            verification=r.choice("verification", VERIFICATION_STATES),
            notes=(r.get("notes", str, "") or "").strip())
        _check_citation(r, d.sources, d.verification, "n/a", source_ids)
        r.finish()
        deferred.append(d)

    if problems:
        raise RulePackError(problems)
    return RulePack(**meta, sources=sources, rules=tuple(rules), applicability=tuple(applicability),
                    deferred=tuple(deferred), _by_id=by_id)
