"""The rule-based approval route for patch jobs.

The approval route comes from fixed rules (SSVC, asset criticality, OT flag) plus thresholds an authorised person
may tighten or loosen within limits, never from the draft, so a generated job cannot lower its own approval level.
Drafts come from the ``sutra_patchdraft`` library (see ``sutra.app.drafting``) and never feed back into routing.
"""

from __future__ import annotations

from .model import Asset, RootCause

ROLE_LABEL = {"manager": "Manager", "vm_analyst": "VM analyst", "vertical_head": "Vertical head", "ciso": "CISO"}
MAX_EXCEPTION_DAYS = 365
UNOWNED = "(no owner)"


def team_of(asset: Asset) -> str:
    return asset.owner or UNOWNED


def route(rc: RootCause, hosts: list[Asset], rules: dict) -> dict:
    """Who must approve. Manager and VM analyst always; the vertical head per the rules; OT always."""
    crown = any(h.criticality >= int(rules.get("crown_jewel_min_criticality", 5)) for h in hosts)
    head_ssvc = set(rules.get("vertical_head_for_ssvc", ["Act", "Attend", "Track*"]))
    full = ["manager", "vm_analyst", "vertical_head"]
    if rc.is_ot:
        return {"steps": full, "type": "staged-plan", "emergency": False,
                "reason": "OT asset: staged plan executed by a plant engineer, with OEM approval and a shutdown slot"}
    emergency = rc.ssvc == "Act" and bool(rules.get("emergency_fast_track_for_act", True))
    if rc.ssvc in head_ssvc or crown:
        why = f"SSVC {rc.ssvc}" if rc.ssvc in head_ssvc else "crown-jewel asset"
        extra = "; the vertical head can approve it as an emergency change" if emergency else ""
        return {"steps": full, "type": "patch-job", "emergency": emergency,
                "reason": f"{why}: needs the vertical head{extra}"}
    return {"steps": ["manager", "vm_analyst"], "type": "patch-job", "emergency": False,
            "reason": f"SSVC {rc.ssvc} on non-critical IT assets: manager and VM analyst are enough"}


def exception_route(rc: RootCause) -> dict:
    """Who must approve accepting the risk instead of fixing it. Fixed rules, not thresholds: accepting risk always
    needs the vertical head, and an actively exploited (SSVC Act) root cause also needs the CISO's final sign-off."""
    steps = ["manager", "vm_analyst", "vertical_head"] + (["ciso"] if rc.ssvc == "Act" else [])
    why = ("SSVC Act: the CISO gives the final sign-off" if rc.ssvc == "Act"
           else "accepting risk needs the vertical head")
    return {"steps": steps, "type": "risk-acceptance", "emergency": False, "reason": f"Risk acceptance: {why}"}
