"""The JSON schemas a model answers in, and the section keys of a board briefing."""

from __future__ import annotations

from .gate import ALL_PROPOSABLE

ROLES = ("supports", "contradicts", "uncertainty", "next_check")
BRIEFING_SECTIONS = ("headline", "top_risks", "coverage", "compliance_clock", "decisions")
SECTION_TITLES = {"headline": "Where we stand", "top_risks": "What drives the risk",
                  "coverage": "How much we can see", "compliance_clock": "The CEA fix clock",
                  "decisions": "What the board is asked to do"}


def claim_schema() -> dict:
    return {
        "type": "object", "additionalProperties": False,
        "required": ["text", "cites", "role", "action"],
        "properties": {
            "text": {"type": "string"},
            "cites": {"type": "array", "items": {"type": "string", "pattern": "^[A-Z][0-9]{1,3}$"}},
            "role": {"type": "string", "enum": list(ROLES)},
            # The only thing a claim can propose. "none" is the usual value; the policy gate checks the rest.
            "action": {"type": "string", "enum": ["none", *ALL_PROPOSABLE]},
        },
    }


def root_cause_schema() -> dict:
    return {"type": "object", "additionalProperties": False, "required": ["claims"],
            "properties": {"claims": {"type": "array", "items": claim_schema()}}}


def briefing_schema() -> dict:
    section = {"type": "object", "additionalProperties": False, "required": ["key", "claims"],
               "properties": {"key": {"type": "string", "enum": list(BRIEFING_SECTIONS)},
                              "claims": {"type": "array", "items": claim_schema()}}}
    return {"type": "object", "additionalProperties": False, "required": ["sections"],
            "properties": {"sections": {"type": "array", "items": section}}}
