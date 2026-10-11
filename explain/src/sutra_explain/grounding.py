"""Checks a model's explanation against the facts it was given. An uncited or unsupported claim is never shown.

A claim is accepted only if all of these hold:

* it cites at least one node, and every cited ref exists in the fact set;
* every ``{ref}`` placeholder in its text is one of the refs it cites (placeholders are how names get into text, and
  the renderer fills them in, so the model never writes a hostname or title);
* every number in its text is a number stored on a node it cites;
* it contains no URL, address, markup, CVE ID that its cited nodes do not carry, or instruction-like wording;
* it does not talk about lowering, closing, ignoring or skipping anything (the ratchet rule: an explanation may
  make Sutra louder, never quieter);
* strong words (exploited, internet, safety, plant, overdue) appear only when a cited node says so.

These are mechanical tests. They do not prove a sentence true, which is why the app shows the cited nodes beside every
claim and why the text is kept short.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from .gate import ALL_PROPOSABLE
from .nodes import REF, FactSet, Node, normalise_number, numbers_in
from .schema import BRIEFING_SECTIONS, ROLES

MAX_TEXT = 320
MAX_CITES = 8
PLACEHOLDER = re.compile(r"\{([^{}]*)\}")
CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
FORBIDDEN = re.compile(
    r"https?:|www\.|\S@\S|\b\d{1,3}(\.\d{1,3}){3}\b|[<>`\\]|\[\w[^\]]*\]\(|"
    r"\b(ignore|disregard|override|bypass|skip|disable|suppress|downgrade|snooze|whitelist|allowlist|exempt)\b|"
    r"\b(safe to ignore|false positive|no action (is )?(needed|required|necessary)|nothing to do|"
    r"can be closed|may be closed|close (it|this|the)|accept(ed)? the risk|risk accept|low priority|"
    r"not (a )?(real|serious) (risk|issue|problem)|mark(ed)? (it |this )?(as )?(resolved|benign|safe|fixed))\b|"
    r"\b(system prompt|instructions?|as an ai|assistant|jailbreak)\b|\bemergency\b|\bapproval[s]? (is |are )?not\b",
    re.I)
WORD_NUMBERS = {"zero": "0", "one": "1", "two": "2", "three": "3", "four": "4", "five": "5", "six": "6",
                "seven": "7", "eight": "8", "nine": "9", "ten": "10", "eleven": "11", "twelve": "12",
                "thirteen": "13", "fourteen": "14", "fifteen": "15", "twenty": "20", "thirty": "30",
                "fifty": "50", "hundred": "100", "thousand": "1000"}
WORD_NUMBER = re.compile(r"\b(" + "|".join(WORD_NUMBERS) + r")\b", re.I)
# Words that describe the real world need a cited node that says so (or, if negated, says the opposite).
NEGATION = r"\b(no|not|without|none|never|isn't|aren't|neither)\b"


def _any(nodes: list[Node], key: str, pred: Callable[[Any], bool]) -> bool:
    return any(key in n.fields and pred(n.fields[key]) for n in nodes)


def _all_known(nodes: list[Node], key: str, pred: Callable[[Any], bool]) -> bool:
    have = [n.fields[key] for n in nodes if key in n.fields]
    return bool(have) and all(pred(v) for v in have)


@dataclass(frozen=True)
class TermRule:
    name: str
    pattern: re.Pattern
    positive: Callable[[list[Node]], bool]
    negative: Callable[[list[Node]], bool]  # what must hold when the sentence denies the thing


TERM_RULES = (
    TermRule("exploitation", re.compile(r"exploit|in the wild|\bKEV\b|proof[- ]of[- ]concept|weaponi[sz]ed", re.I),
             lambda ns: _any(ns, "exploitation", lambda v: v in ("poc", "active"))
             or _any(ns, "cves_active", lambda v: v > 0) or _any(ns, "cves_poc", lambda v: v > 0),
             lambda ns: _all_known(ns, "exploitation", lambda v: v == "none")),
    TermRule("internet exposure", re.compile(r"\binternet\b|publicly|externally exposed|exposed to the (web|outside)",
                                             re.I),
             lambda ns: _any(ns, "exposure", lambda v: v == "open") or _any(ns, "zone", lambda v: v == "internet"),
             lambda ns: _all_known(ns, "exposure", lambda v: v != "open")),
    TermRule("safety", re.compile(r"\bsafety\b|human (life|harm)|injur", re.I),
             lambda ns: _any(ns, "safety_critical", bool) or _any(ns, "human_impact", lambda v: v == "very high"),
             lambda ns: _all_known(ns, "safety_critical", lambda v: not v)),
    TermRule("operational technology", re.compile(r"\bOT\b|operational technology|\bplant\b|control system|"
                                                  r"industrial|\bSCADA\b|\bPLC\b", re.I),
             lambda ns: _any(ns, "is_ot", bool) or _any(ns, "zone", lambda v: v.startswith("ot-")),
             lambda ns: _all_known(ns, "is_ot", lambda v: not v)),
    TermRule("overdue", re.compile(r"overdue|past (its |their )?(due|deadline)|missed (the |its )?deadline", re.I),
             lambda ns: _any(ns, "cea_overdue", lambda v: v > 0),
             lambda ns: _all_known(ns, "cea_overdue", lambda v: v == 0)),
    TermRule("injection suspects", re.compile(r"(addressed|aimed|directed) (to|at) (an )?(AI|model)", re.I),
             lambda ns: _any(ns, "injection_suspects", lambda v: v > 0),
             lambda ns: _all_known(ns, "injection_suspects", lambda v: v == 0)),
)


@dataclass(frozen=True)
class Claim:
    text: str  # may contain {ref} placeholders
    cites: tuple[str, ...]
    role: str = "supports"
    action: str = "none"


def check_claim(raw: Any, facts: FactSet, n: int = 1) -> tuple[Claim | None, list[str]]:
    """Validate one claim (``n`` is its position, used in messages so rejected text is never echoed back).
    Returns the claim and no errors, or None and the reasons."""
    if not isinstance(raw, dict):
        return None, ["a claim is not an object"]
    text, cites = raw.get("text"), raw.get("cites")
    role, action = raw.get("role", "supports"), raw.get("action", "none")
    errs: list[str] = []
    if not isinstance(text, str) or not text.strip():
        return None, ["a claim has no text"]
    label = f"claim {n}"
    if not isinstance(cites, list) or not cites or not all(isinstance(c, str) for c in cites):
        return None, [f"{label} cites nothing"]
    if len(cites) > MAX_CITES:
        errs.append(f"{label} cites more than {MAX_CITES} nodes")
    unknown = [c for c in cites if c not in facts]
    if unknown:
        errs.append(f"{label} cites {', '.join(unknown[:3])}, which are not in the facts")
        return None, errs
    if len(text) > MAX_TEXT:
        errs.append(f"{label} is longer than {MAX_TEXT} characters")
    if role not in ROLES:
        errs.append(f"{label} has role {role!r}")
    if action != "none" and action not in ALL_PROPOSABLE:
        errs.append(f"{label} proposes {action!r}, which is not an allowed action")
    nodes = [facts.nodes[c] for c in dict.fromkeys(cites)]

    for ph in PLACEHOLDER.findall(text):
        if ph not in cites:
            errs.append(f"{label} uses {{{ph}}}, which it does not cite")
    if "{" in PLACEHOLDER.sub("", text) or "}" in PLACEHOLDER.sub("", text):
        errs.append(f"{label} has a stray brace")
    bare = PLACEHOLDER.sub(" ", text)
    for n in nodes:  # a literal ID or ref is fine (it is a citation); strip so its digits are not read as figures
        for token in (n.ref, n.node_id):
            bare = re.sub(rf"(?<![\w-]){re.escape(token)}(?![\w-])", " ", bare)

    if FORBIDDEN.search(bare):
        errs.append(f"{label} contains wording or markup that explanations may not use "
                    f"({FORBIDDEN.search(bare).group(0)!r})")
    allowed_cves = {n.fields["cve"].upper() for n in nodes if "cve" in n.fields}
    for c in CVE.findall(bare):
        if c.upper() not in allowed_cves:
            errs.append(f"{label} names {c}, which no cited node carries")
    allowed = set().union(*(n.allowed_numbers() for n in nodes)) if nodes else set()
    bare_wo_cve = CVE.sub(" ", bare)
    for num in numbers_in(bare_wo_cve):
        if num not in allowed:
            errs.append(f"{label} states {num}, which no cited node carries")
    for word in WORD_NUMBER.findall(bare_wo_cve):
        if normalise_number(WORD_NUMBERS[word.lower()]) not in allowed:
            errs.append(f"{label} states {word}, which no cited node carries")
    for rule in TERM_RULES:
        m = rule.pattern.search(bare)
        if not m:
            continue
        negated = re.search(NEGATION + r"[^.;]{0,40}(?:" + rule.pattern.pattern + ")", bare, re.I) is not None
        ok = rule.negative(nodes) if negated else rule.positive(nodes)
        if not ok:
            errs.append(f"{label} says {m.group(0)!r} ({rule.name}) but its cited nodes do not support that")
    if errs:
        return None, errs
    return Claim(text.strip(), tuple(dict.fromkeys(cites)), role, action), []


def check_claims(raw: Any, facts: FactSet, minimum: int = 1) -> tuple[list[Claim], list[str]]:
    errs: list[str] = []
    if not isinstance(raw, list):
        return [], ["claims is not a list"]
    claims: list[Claim] = []
    for n, item in enumerate(raw, 1):
        claim, e = check_claim(item, facts, n)
        if claim:
            claims.append(claim)
        errs += e
    if len(claims) < minimum and not errs:
        errs.append("the explanation has no claims")
    return claims, errs


def check_root_cause(data: Any, facts: FactSet) -> tuple[list[Claim], list[str]]:
    if not isinstance(data, dict) or "claims" not in data:
        return [], ["the reply has no claims"]
    claims, errs = check_claims(data["claims"], facts)
    if not errs and not any(c.role == "supports" for c in claims):
        errs.append("no claim supports the explanation")
    if not errs and "R1" not in {r for c in claims for r in c.cites}:
        errs.append("no claim cites the root cause itself (R1)")
    return claims, errs


def check_briefing(data: Any, facts: FactSet) -> tuple[dict[str, list[Claim]], list[str]]:
    if not isinstance(data, dict) or not isinstance(data.get("sections"), list):
        return {}, ["the reply has no sections"]
    out: dict[str, list[Claim]] = {}
    errs: list[str] = []
    for sec in data["sections"]:
        key = sec.get("key") if isinstance(sec, dict) else None
        if key not in BRIEFING_SECTIONS:
            errs.append(f"unknown section {key!r}")
            continue
        if key in out:
            errs.append(f"section {key} appears twice")
            continue
        claims, e = check_claims(sec.get("claims"), facts)
        out[key] = claims
        errs += e
    missing = [k for k in BRIEFING_SECTIONS if k not in out]
    if missing:
        errs.append(f"missing sections: {', '.join(missing)}")
    return out, errs


def refs_used(claims: Iterable[Claim]) -> set[str]:
    return {r for c in claims for r in c.cites if REF.fullmatch(r)}
