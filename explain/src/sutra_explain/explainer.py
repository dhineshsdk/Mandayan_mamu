"""Writes explanations with a model when one is configured and rules otherwise. Every claim passes ``grounding``.

The model sees only a ``FactSet`` (typed fields, short refs) and answers in a fixed schema. Its claims are checked;
a rejected answer is retried once with the reasons, and if it still fails, the model is unreachable or it declines,
the rule-written explanation is used and says why. Proposed actions go through the policy gate, so an explanation
can suggest a ticket or a notification and can never close, lower or suppress anything.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .clients import ModelDeclined, ModelTruncated, ModelUnavailable
from .gate import PolicyGate, Proposal
from .grounding import Claim, check_briefing, check_root_cause
from .nodes import FactSet
from .prompt import BRIEFING_TASK, ROOT_CAUSE_TASK, RULES, user_message
from .schema import BRIEFING_SECTIONS, SECTION_TITLES, briefing_schema, root_cause_schema
from .template import briefing_claims, root_cause_claims

log = logging.getLogger("sutra_explain")
PLACEHOLDER = re.compile(r"\{([A-Z][0-9]{1,3})\}")
GATE = PolicyGate()


def render_text(text: str, facts: FactSet) -> str:
    """Fill {ref} placeholders with the node's display label, which only people ever see."""
    def label(m: re.Match) -> str:
        n = facts.get(m.group(1))
        shown = (n.label or n.node_id) if n else m.group(1)
        return " ".join(shown.split())[:120]
    return PLACEHOLDER.sub(label, text)


@dataclass
class Explanation:
    kind: str  # root_cause | briefing
    subject: str
    source: str  # ai | template
    model: str | None = None
    fallback_reason: str | None = None
    attempts: int = 0
    claims: list[Claim] = field(default_factory=list)  # root_cause
    sections: dict[str, list[Claim]] = field(default_factory=dict)  # briefing
    held_actions: list[str] = field(default_factory=list)

    def all_claims(self) -> list[Claim]:
        return self.claims or [c for k in BRIEFING_SECTIONS for c in self.sections.get(k, [])]

    def _claim(self, c: Claim, facts: FactSet) -> dict[str, Any]:
        return {"text": render_text(c.text, facts), "role": c.role, "action": c.action,
                "cites": [facts.nodes[r].public() for r in c.cites]}

    def to_dict(self, facts: FactSet) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind, "subject": self.subject, "source": self.source, "model": self.model,
                               "fallback_reason": self.fallback_reason, "attempts": self.attempts,
                               "held_actions": self.held_actions}
        if self.kind == "root_cause":
            out["claims"] = [self._claim(c, facts) for c in self.claims]
        else:
            out["sections"] = [{"key": k, "title": SECTION_TITLES[k],
                                "claims": [self._claim(c, facts) for c in self.sections.get(k, [])]}
                               for k in BRIEFING_SECTIONS]
        return out


def _through_gate(claims: list[Claim], facts: FactSet, held: list[str]) -> list[Claim]:
    out = []
    for c in claims:
        if c.action != "none":
            lane = "ot" if any(facts.nodes[r].fields.get("is_ot") or str(facts.nodes[r].fields.get("zone", ""))
                               .startswith("ot-") for r in c.cites) else "it"
            d = GATE.check(Proposal(c.action, c.cites[0], lane))
            if not d.allowed or d.needs_human:
                held.append(f"{c.action}: {d.reason}")
                c = Claim(c.text, c.cites, c.role, "none")
        out.append(c)
    return out


class Explainer:
    def __init__(self, client: Any = None, attempts: int = 2, max_tokens: int = 4000, unavailable: str = ""):
        self.client, self.attempts, self.max_tokens = client, attempts, max_tokens
        self.unavailable = unavailable or ("no AI model is configured" if client is None else "")

    @classmethod
    def from_config(cls, cfg) -> Explainer:
        client, why = cfg.build_client()
        return cls(client, cfg.attempts, cfg.max_tokens, why)

    @property
    def ai_available(self) -> bool:
        return self.client is not None

    def explain_root_cause(self, facts: FactSet) -> Explanation:
        def check(data):
            return check_root_cause(data, facts)
        claims, meta = self._run(facts, ROOT_CAUSE_TASK, root_cause_schema(), check,
                                 lambda: root_cause_claims(facts), "root_cause")
        held: list[str] = []
        return Explanation("root_cause", facts.subject, claims=_through_gate(claims, facts, held), held_actions=held,
                           **meta)

    def brief_board(self, facts: FactSet) -> Explanation:
        def check(data):
            return check_briefing(data, facts)
        sections, meta = self._run(facts, BRIEFING_TASK, briefing_schema(), check,
                                   lambda: briefing_claims(facts), "briefing")
        held: list[str] = []
        sections = {k: _through_gate(v, facts, held) for k, v in sections.items()}
        return Explanation("briefing", facts.subject, sections=sections, held_actions=held, **meta)

    def _run(self, facts: FactSet, task: str, schema: dict, check: Callable, template: Callable, kind: str):
        reason, rejected = self.unavailable, []
        if self.client is not None:
            for attempt in range(1, self.attempts + 1):
                try:
                    reply = self.client.complete(RULES, user_message(task, facts, rejected), schema, self.max_tokens)
                    data = json.loads(reply.text)
                except ModelDeclined:
                    reason = "the model declined to write this explanation"
                    break
                except ModelUnavailable as e:
                    reason = str(e)
                    break
                except ModelTruncated:
                    rejected, reason = ["the reply was cut off; write less"], "the model's reply was cut off"
                    continue
                except ValueError:
                    rejected, reason = ["the reply was not valid JSON"], "the model's reply was not valid JSON"
                    continue
                result, errors = check(data)
                if not errors:
                    return result, {"source": "ai", "model": reply.model, "attempts": attempt}
                rejected = errors
                reason = (f"the model's explanation failed Sutra's checks after {attempt} attempt(s): "
                          + "; ".join(errors[:3]) + (f" (and {len(errors) - 3} more)" if len(errors) > 3 else ""))
                log.warning("%s %s attempt %d rejected: %s", kind, facts.subject, attempt, "; ".join(errors[:10]))
        raw = template()
        if kind == "root_cause":
            data: Any = {"claims": [{"text": c.text, "cites": list(c.cites), "role": c.role, "action": c.action}
                                    for c in raw]}
        else:
            data = {"sections": [{"key": k, "claims": [{"text": c.text, "cites": list(c.cites), "role": c.role,
                                                          "action": c.action} for c in v]}
                                 for k, v in raw.items()]}
        result, errors = check(data)
        if errors:  # the rules wrote something the checks reject: a bug here, not bad input
            raise RuntimeError(f"rule-written {kind} for {facts.subject} failed its checks: {errors}")
        return result, {"source": "template", "model": None, "fallback_reason": reason or None,
                        "attempts": self.attempts if self.client is not None else 0}
