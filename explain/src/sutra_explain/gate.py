"""The policy gate: plain code with a short allow-list, between anything an AI proposes and anything that happens.

Fixed verbs only. Operational technology verbs stop at notify, ticket and stage; a person carries out the change.
The ratchet rule lives here too: a proposal may raise risk on its own evidence, but closing, lowering, suppressing or
accepting anything needs a second independent source and a named person, and the gate never performs it itself.
"""

from __future__ import annotations

from dataclasses import dataclass

IT_VERBS = frozenset({"open_ticket", "open_pull_request", "stage_change", "notify", "request_rescan"})
OT_VERBS = frozenset({"open_ticket", "stage_change", "notify", "request_rescan"})
LOWERING_VERBS = frozenset({"close", "suppress", "accept_risk", "lower_priority", "mark_false_positive", "downgrade",
                            "snooze", "exclude"})
ALL_PROPOSABLE = sorted(IT_VERBS)


@dataclass(frozen=True)
class Proposal:
    verb: str
    target: str  # a ref or ID; the gate does not interpret it
    lane: str = "it"  # "it" | "ot"
    second_source: str = ""  # what independent evidence supports lowering, if that is what this is
    named_person: str = ""  # who takes responsibility for lowering


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    needs_human: bool = False


class PolicyGate:
    def check(self, p: Proposal) -> Decision:
        if p.verb in LOWERING_VERBS:
            if p.second_source.strip() and p.named_person.strip():
                # Allowed to be *put to a person*, never executed here.
                return Decision(True, "lowering needs a person to confirm; it was not carried out", needs_human=True)
            return Decision(False, "lowering, closing or suppressing needs a second independent source and a "
                                   "named person")
        allowed = OT_VERBS if p.lane == "ot" else IT_VERBS
        if p.verb in allowed:
            return Decision(True, "allowed")
        if p.verb in IT_VERBS:
            return Decision(False, f"{p.verb} is not allowed on operational technology; it stops at read and stage")
        return Decision(False, f"{p.verb!r} is not an allowed action")

    def filter(self, proposals: list[Proposal]) -> tuple[list[Proposal], list[tuple[Proposal, Decision]]]:
        """Proposals that may go ahead, and the ones that may not (or that need a person) with the reason."""
        ok: list[Proposal] = []
        held: list[tuple[Proposal, Decision]] = []
        for p in proposals:
            d = self.check(p)
            if d.allowed and not d.needs_human:
                ok.append(p)
            else:
                held.append((p, d))
        return ok, held
