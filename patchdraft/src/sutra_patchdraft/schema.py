"""The JSON schemas a model draft must match, one per lane.

IT drafts describe a job a patch tool can run after approval. OT drafts describe a staged plan a plant engineer
carries out by hand; their verb list has no deploy, reboot or automation step, and there is no ``tool`` field, so an
OT draft cannot be shaped as an executable job. Neither schema has a field for approvers, route or urgency: the
approval route comes from fixed rules outside this package.

The schemas avoid keywords structured outputs does not enforce (lengths, numeric ranges); ``grounding.validate``
checks those limits instead.
"""

from __future__ import annotations

IT_TOOLS = (
    "Intune",
    "SCCM",
    "Ansible",
    "Group Policy",
    "Image pipeline (Packer)",
    "Windows LAPS / password vault",
    "Manual change by the owning team",
)

OT_TOOL = "Staged plan, executed by a plant engineer"

# Verbs a step may use, with the label shown to approvers.
IT_VERBS = {
    "capture_health_baseline": "Capture a service health baseline",
    "snapshot": "Take a snapshot or backup",
    "deploy_update": "Deploy the update",
    "rebuild_image": "Rebuild the golden image",
    "apply_config_change": "Apply the configuration change",
    "rotate_credential": "Rotate the credential",
    "reboot": "Reboot",
    "verify_service_health": "Verify service health against the baseline",
    "rescan": "Rescan to prove the fix",
    "notify_owners": "Notify application owners",
}

OT_VERBS = {
    "request_oem_approval": "Request OEM approval",
    "hold_compensating_control": "Hold the compensating control until the shutdown",
    "backup_configuration": "Back up firmware, logic and HMI images",
    "confirm_shutdown_slot": "Confirm the shutdown slot with operations",
    "apply_update_manually": "Apply the update by hand",
    "functional_check_with_operations": "Run functional checks with operations",
    "verify_with_passive_monitor": "Verify with the passive OT monitor",
    "safe_rescan": "Run a safe rescan",
}

# Verbs that carry out a change; every change in the fact table needs at least one of these steps.
APPLY_VERBS = {"deploy_update", "rebuild_image", "apply_config_change", "rotate_credential", "apply_update_manually"}
# Verbs that prove a change worked; every draft must end its work with one.
VERIFY_VERBS = {"rescan", "verify_service_health", "verify_with_passive_monitor", "safe_rescan"}

LIMITS = {
    "summary": 400,
    "text": 600,  # step detail, check text, reasons
    "rings": 6,
    "steps": 30,
    "list": 12,  # prechecks, rollback steps, assumptions, compensating controls
}


def _refs() -> dict:
    return {"type": "array", "items": {"type": "string"}}


def _obj(properties: dict) -> dict:
    return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}


def schema_for(lane: str) -> dict:
    if lane not in ("it", "ot"):
        raise ValueError(f"unknown lane {lane!r}")
    verbs = IT_VERBS if lane == "it" else OT_VERBS
    step = _obj({
        "action": {"type": "string", "enum": sorted(verbs)},
        "ring": {"type": "integer", "description": "1-based ring or stage number, or 0 for a step before or "
                                                   "across all rings"},
        "changes": {**_refs(), "description": "C refs this step applies; empty for steps that apply nothing"},
        "detail": {"type": "string"},
        "cites": {**_refs(), "description": "H, F, C or R1 refs that justify this step"},
    })
    cited_text = _obj({"text": {"type": "string"}, "cites": _refs()})
    props: dict = {
        "summary": {"type": "string"},
        "excluded_hosts": {"type": "array", "items": _obj({"host": {"type": "string"},
                                                           "reason": {"type": "string"}})},
        "rings": {"type": "array", "items": _obj({"name": {"type": "string"}, "hosts": _refs(),
                                                  "purpose": {"type": "string"}})},
        "steps": {"type": "array", "items": step},
        "prechecks": {"type": "array", "items": cited_text},
        "rollback": _obj({"trigger": {"type": "string"}, "steps": {"type": "array", "items": {"type": "string"}},
                          "cites": _refs()}),
        "assumptions": {"type": "array", "items": {"type": "string"},
                        "description": "Facts the plan relies on that the input does not establish"},
    }
    if lane == "it":
        props = {"summary": props.pop("summary"), "tool": {"type": "string", "enum": list(IT_TOOLS)}, **props}
    else:
        props["oem_approval_request"] = _obj({"changes": _refs(), "detail": {"type": "string"}, "cites": _refs()})
        props["compensating_controls"] = {"type": "array", "items": _obj({
            "control": {"type": "string"}, "hosts": _refs(), "cites": _refs()})}
    return _obj(props)
