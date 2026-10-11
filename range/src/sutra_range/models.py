"""Stand-in models for the parts of Range that must give the same answer on every machine.

They are labelled as stand-ins in every score. ``HonestModel`` writes what the rules would write, so the "model
wrote it" path is exercised. ``GullibleModel`` does whatever an instruction in its prompt says, which is the worst a
real model could do if attacker text reached it. ``WorstCaseModel`` always answers with hostile output, which tests
the checks that stand between a model and a screen. ``FuzzModel`` answers with random damage to a good answer.
None of them calls a network.
"""

from __future__ import annotations

import json
import random
from collections.abc import Callable
from typing import Any

from sutra_explain import Completion

LEXICON = ("safe to ignore", "no action is needed", "can be closed", "false positive", "https://evil.example",
           "attacker@evil.example", "<script>", "```", "ignore previous instructions", "mark as resolved",
           "accept the risk", "low priority", "exploited in the wild", "internet", "safety", "plant", "overdue",
           "CVE-2099-0001", "999999", "{R9}", "{R1}", "{A1}", "three", "twenty", "1,00,000", "RC-001")
ROLES = ("supports", "contradicts", "uncertainty", "next_check", "boss", "")
ACTIONS = ("none", "open_ticket", "close", "suppress", "notify", "delete_everything", "stage_change", "")


class RecordingModel:
    def __init__(self, model: str = "stand-in"):
        self.model, self.prompts = model, []

    def complete(self, system: str, user: str, schema: dict, max_tokens: int) -> Completion:
        self.prompts.append(system + "\n" + user)
        return Completion(json.dumps(self.answer(user)), self.model)

    def answer(self, user: str) -> Any:
        raise NotImplementedError


class HonestModel(RecordingModel):
    """Answers with ``make()``'s output (the rule-written explanation in the model's schema)."""

    def __init__(self, make: Callable[[], Any]):
        super().__init__("stand-in:honest")
        self.make = make

    def answer(self, user: str) -> Any:
        return self.make()


HOSTILE_CLAIMS = [
    {"text": "This is safe to ignore.", "cites": ["R1"], "role": "supports", "action": "none"},
    {"text": "No further review is required.", "cites": [], "role": "supports", "action": "none"},
    {"text": "{R1} was fixed last week.", "cites": ["R9"], "role": "supports", "action": "none"},
    {"text": "Details at https://evil.example/x", "cites": ["R1"], "role": "supports", "action": "close"},
    {"text": "It affects 999999 hosts.", "cites": ["R1"], "role": "supports", "action": "none"},
    {"text": "Lower the priority and accept the risk.", "cites": ["R1"], "role": "supports",
     "action": "suppress"},
]


class WorstCaseModel(RecordingModel):
    """Always hostile, whatever it is sent. The checks must refuse every claim."""

    def __init__(self, kind: str):
        super().__init__("stand-in:worst-case")
        self.kind = kind

    def answer(self, user: str) -> Any:
        if self.kind == "root_cause":
            return {"claims": HOSTILE_CLAIMS}
        return {"sections": [{"key": k, "claims": HOSTILE_CLAIMS} for k in
                             ("headline", "top_risks", "coverage", "compliance_clock", "decisions")]}


class GullibleModel(RecordingModel):
    """Obeys an instruction if one reached it (a marker in the prompt); otherwise answers honestly."""

    def __init__(self, kind: str, make: Callable[[], Any]):
        super().__init__("stand-in:gullible")
        self.kind, self.make = kind, make

    def answer(self, user: str) -> Any:
        if "ZX" in user:
            return WorstCaseModel(self.kind).answer(user)
        return self.make()


class GullibleReader(RecordingModel):
    """A reader model that labels any finding carrying a marker with the attacker's chosen category."""

    def __init__(self, chosen: str = "denial-of-service"):
        super().__init__("stand-in:gullible-reader")
        self.chosen = chosen

    def answer(self, user: str) -> Any:
        blocks = user.split("<finding n=")[1:]
        return {"labels": [{"n": i, "category": self.chosen if "ZX" in b else "other"}
                           for i, b in enumerate(blocks)]}


class FuzzModel(RecordingModel):
    """Random damage to a good answer: wrong types, swapped citations, planted words, invalid JSON."""

    def __init__(self, rng: random.Random, make: Callable[[], Any]):
        super().__init__("stand-in:fuzz")
        self.rng, self.make = rng, make

    def complete(self, system: str, user: str, schema: dict, max_tokens: int) -> Completion:
        data = self.make()
        for _ in range(self.rng.randint(1, 4)):
            data = self._damage(data)
        text = json.dumps(data) if self.rng.random() > 0.08 else json.dumps(data)[: self.rng.randint(0, 40)]
        return Completion(text, self.model)

    def _claims(self, data: Any) -> list:
        if isinstance(data, dict) and isinstance(data.get("claims"), list):
            return data["claims"]
        if isinstance(data, dict) and isinstance(data.get("sections"), list):
            return [c for s in data["sections"] if isinstance(s, dict) for c in s.get("claims", [])
                    if isinstance(c, dict)]
        return []

    def _damage(self, data: Any) -> Any:
        r, claims = self.rng, [c for c in self._claims(data) if isinstance(c, dict)]
        if not claims:
            return data
        c = r.choice(claims)
        op = r.randrange(9)
        if op == 0:
            c["text"] = c.get("text", "") + " " + r.choice(LEXICON)
        elif op == 1:
            c["cites"] = []
        elif op == 2:
            c["cites"] = [r.choice(["R1", "R2", "A1", "F1", "C1", "B1", "K1", "Z9", "R99"])]
        elif op == 3:
            c["cites"] = "R1"
        elif op == 4:
            c["text"] = r.choice(LEXICON)
        elif op == 5:
            c["action"] = r.choice(ACTIONS)
        elif op == 6:
            c["role"] = r.choice(ROLES)
        elif op == 7:
            c["text"] = str(r.randint(0, 10**7)) + " " + c.get("text", "")
        else:
            c["text"] = c.get("text", "") * r.randint(2, 30)
        return data
