"""Checks a raw draft (from a model or the template) before anyone sees it.

A draft passes only if it matches its lane's schema, every ref points at a real host, finding or change, each host
sits in exactly one ring or is excluded with a reason, every change is applied by a step of the right kind, the plan
ends with verification, and no free text carries a version, KB number, CVE, advisory ID, IP or URL that is absent
from the input. OT drafts also may not name patch tools or scripts, and no draft may talk about skipping approvals
or emergency status, which the rules engine owns.

The schema check repeats what structured outputs enforces on the API side, because a draft can also come from a
local model or a mocked client, and because a schema cannot express the cross-field rules.
"""

from __future__ import annotations

import re
from typing import Any

from .facts import ROOT_CAUSE_REF, Facts
from .schema import APPLY_VERBS, LIMITS, VERIFY_VERBS, schema_for

# Which change kinds each apply verb may carry.
VERB_CHANGE_KINDS = {
    "deploy_update": {"package", "windows-update", "other"},
    "rebuild_image": {"package", "windows-update"},
    "apply_config_change": {"config", "other"},
    "rotate_credential": {"credential"},
    "apply_update_manually": {"package", "windows-update", "config", "credential", "other"},
}

_TOKEN_PATTERNS = {
    "CVE ID": re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I),
    "KB number": re.compile(r"\bKB\d{6,8}\b", re.I),
    "advisory ID": re.compile(
        r"\b(?:RHSA|RHBA|RHEA|ELSA|ALAS\d*|DSA|DLA|USN|MS\d{2}|ADV|SSA|ICSA|FG-IR|cisco-sa|VMSA|APSB|GHSA|SUSE-SU)"
        r"[-:][\w:.\-]*\d[\w:.\-]*", re.I),
    "version or address": re.compile(r"(?<![\w.])v?\d+(?:\.\d+)+(?:[-_~+:][0-9A-Za-z][0-9A-Za-z.~+_:\-]*)?"),
    "URL": re.compile(r"\b(?:https?|ftp)://\S+", re.I),
}
_OT_AUTOMATION = re.compile(r"\b(ansible|intune|sccm|wsus|psexec|winrm|powershell|playbook|bash script|cron)\b",
                            re.I)
_APPROVAL_TALK = re.compile(
    r"\b(skip|skipping|bypass|bypassing|waive|waiving|no need for|not require|does not need|without)\b[^.;\n]{0,40}"
    r"\bapprov", re.I)
_EMERGENCY = re.compile(r"\bemergency\b", re.I)


def _type_ok(value: Any, kind: str) -> bool:
    if kind == "object":
        return isinstance(value, dict)
    if kind == "array":
        return isinstance(value, list)
    if kind == "string":
        return isinstance(value, str)
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "boolean":
        return isinstance(value, bool)
    return False


def check_schema(value: Any, schema: dict, path: str, errors: list[str]) -> None:
    if not _type_ok(value, schema["type"]):
        errors.append(f"{path}: expected {schema['type']}")
        return
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {str(value)[:60]!r} is not one of the allowed values")
    if schema["type"] == "object":
        props = schema["properties"]
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}.{key}: missing")
        for key in value:
            if key not in props:
                errors.append(f"{path}.{str(key)[:40]}: field not allowed")
            else:
                check_schema(value[key], props[key], f"{path}.{key}", errors)
    elif schema["type"] == "array":
        for i, item in enumerate(value):
            check_schema(item, schema["items"], f"{path}[{i}]", errors)


def _free_text(raw: dict) -> list[tuple[str, str]]:
    """Every string a person will read, with its path. Ref lists and enum values are checked separately."""
    out = [("summary", raw["summary"])]
    out += [(f"excluded_hosts[{i}].reason", e["reason"]) for i, e in enumerate(raw["excluded_hosts"])]
    for i, r in enumerate(raw["rings"]):
        out += [(f"rings[{i}].name", r["name"]), (f"rings[{i}].purpose", r["purpose"])]
    out += [(f"steps[{i}].detail", s["detail"]) for i, s in enumerate(raw["steps"])]
    out += [(f"prechecks[{i}].text", p["text"]) for i, p in enumerate(raw["prechecks"])]
    out += [("rollback.trigger", raw["rollback"]["trigger"])]
    out += [(f"rollback.steps[{i}]", s) for i, s in enumerate(raw["rollback"]["steps"])]
    out += [(f"assumptions[{i}]", a) for i, a in enumerate(raw["assumptions"])]
    if "oem_approval_request" in raw:
        out += [("oem_approval_request.detail", raw["oem_approval_request"]["detail"])]
        out += [(f"compensating_controls[{i}].control", c["control"])
                for i, c in enumerate(raw["compensating_controls"])]
    return out


def ungrounded_tokens(text: str, corpus: str) -> list[tuple[str, str]]:
    found = []
    for label, pattern in _TOKEN_PATTERNS.items():
        for m in pattern.finditer(text):
            token = m.group(0).rstrip(".,;:)]}'\"").lower()
            if token and token not in corpus:
                found.append((label, m.group(0).rstrip(".,;:)]}'\"")))
    return found


def validate(raw: Any, lane: str, facts: Facts, corpus: str) -> list[str]:
    """Return the reasons a raw draft is unusable; an empty list means it passed."""
    errors: list[str] = []
    check_schema(raw, schema_for(lane), "draft", errors)
    if errors:
        return errors  # the cross-field checks below assume the shape is right

    host_refs, change_refs, all_refs = set(facts.hosts), set(facts.changes), facts.all_refs

    def refs_in(values: list[str], allowed: set[str], path: str) -> None:
        for v in values:
            if v not in allowed:
                errors.append(f"{path}: unknown ref {v[:40]!r}")

    # Lengths and counts
    if not raw["summary"].strip():
        errors.append("summary: empty")
    for path, text in _free_text(raw):
        limit = LIMITS["summary"] if path == "summary" else LIMITS["text"]
        if len(text) > limit:
            errors.append(f"{path}: longer than {limit} characters")
    if not 1 <= len(raw["rings"]) <= LIMITS["rings"]:
        errors.append(f"rings: need 1 to {LIMITS['rings']} rings")
    if not 1 <= len(raw["steps"]) <= LIMITS["steps"]:
        errors.append(f"steps: need 1 to {LIMITS['steps']} steps")
    for key in ("prechecks", "assumptions"):
        if len(raw[key]) > LIMITS["list"]:
            errors.append(f"{key}: more than {LIMITS['list']} items")
    if not raw["prechecks"]:
        errors.append("prechecks: at least one is needed")
    if not raw["rollback"]["steps"] or not raw["rollback"]["trigger"].strip():
        errors.append("rollback: needs a trigger and at least one step")

    # Hosts: each in exactly one ring, or excluded with a reason
    excluded = [e["host"] for e in raw["excluded_hosts"]]
    refs_in(excluded, host_refs, "excluded_hosts")
    for i, e in enumerate(raw["excluded_hosts"]):
        if not e["reason"].strip():
            errors.append(f"excluded_hosts[{i}]: needs a reason")
    placed: list[str] = []
    names = set()
    for i, ring in enumerate(raw["rings"]):
        refs_in(ring["hosts"], host_refs, f"rings[{i}].hosts")
        if not ring["hosts"]:
            errors.append(f"rings[{i}]: has no hosts")
        if not ring["name"].strip() or ring["name"].strip().lower() in names:
            errors.append(f"rings[{i}]: needs a unique name")
        names.add(ring["name"].strip().lower())
        placed += ring["hosts"]
    seen = placed + excluded
    dupes = sorted({h for h in seen if seen.count(h) > 1})
    if dupes:
        errors.append(f"rings: hosts placed more than once: {', '.join(dupes)}")
    missing = sorted(host_refs - set(seen), key=lambda r: int(r[1:]))
    if missing:
        errors.append(f"rings: hosts in no ring and not excluded: {', '.join(missing)}")
    if not placed:
        errors.append("rings: every host is excluded, so the job does nothing")

    # Steps: every change reaches every ring that holds one of its hosts, and verification follows the last change
    applied: dict[int, set[str]] = {}
    last_apply, last_verify = -1, -1
    for i, step in enumerate(raw["steps"]):
        path = f"steps[{i}]"
        if not 0 <= step["ring"] <= len(raw["rings"]):
            errors.append(f"{path}.ring: {step['ring']} is not 0 or a ring number")
        refs_in(step["changes"], change_refs, f"{path}.changes")
        refs_in(step["cites"], all_refs, f"{path}.cites")
        if not step["detail"].strip():
            errors.append(f"{path}.detail: empty")
        action = step["action"]
        if action in APPLY_VERBS:
            last_apply = i
            if not step["changes"]:
                errors.append(f"{path}: {action} must name the C refs it applies")
            for c in step["changes"]:
                if c in facts.changes and facts.changes[c].kind not in VERB_CHANGE_KINDS[action]:
                    errors.append(f"{path}: {action} cannot apply {c}, a {facts.changes[c].kind} change")
                elif action != "rebuild_image":  # a new image does not patch the hosts already running
                    applied.setdefault(step["ring"], set()).add(c)
        elif step["changes"]:
            errors.append(f"{path}: only apply steps may name changes, not {action}")
        if action in VERIFY_VERBS:
            last_verify = i
    everywhere = applied.get(0, set())
    for n, ring in enumerate(raw["rings"], 1):
        members = set(ring["hosts"])
        for c, change in facts.changes.items():
            if members & set(change.host_refs) and c not in everywhere | applied.get(n, set()):
                errors.append(f"steps: no step applies {c} to ring {n} ({ring['name'][:40]})")
    if last_verify < last_apply or last_verify == -1:
        errors.append("steps: the plan must verify the fix after the last change")

    for i, p in enumerate(raw["prechecks"]):
        refs_in(p["cites"], all_refs, f"prechecks[{i}].cites")
    refs_in(raw["rollback"]["cites"], all_refs, "rollback.cites")

    # OT: a staged, human-run plan
    if lane == "ot":
        oem = raw["oem_approval_request"]
        refs_in(oem["changes"], change_refs, "oem_approval_request.changes")
        refs_in(oem["cites"], all_refs, "oem_approval_request.cites")
        if not oem["changes"]:
            errors.append("oem_approval_request: must name the changes the OEM approves")
        if not raw["compensating_controls"]:
            errors.append("compensating_controls: an OT plan must hold at least one until the shutdown")
        for i, c in enumerate(raw["compensating_controls"]):
            refs_in(c["hosts"], host_refs, f"compensating_controls[{i}].hosts")
            refs_in(c["cites"], all_refs, f"compensating_controls[{i}].cites")
        if not any(s["action"] == "request_oem_approval" for s in raw["steps"]):
            errors.append("steps: an OT plan must include a step requesting OEM approval")

    # Free text: nothing made up, no automation in OT, no say in approvals
    for path, text in _free_text(raw):
        for label, token in ungrounded_tokens(text, corpus):
            errors.append(f"{path}: {label} {token[:60]!r} does not appear in the input data")
        if lane == "ot" and _OT_AUTOMATION.search(text):
            errors.append(f"{path}: OT plans are carried out by hand; do not name patch tools or scripts")
        if _APPROVAL_TALK.search(text):
            errors.append(f"{path}: approvals are set by Sutra's rules; the draft must not discuss skipping them")
        if _EMERGENCY.search(text):
            errors.append(f"{path}: emergency status is set by Sutra's rules, not the draft")
    return errors


__all__ = ["validate", "check_schema", "ungrounded_tokens", "ROOT_CAUSE_REF"]
