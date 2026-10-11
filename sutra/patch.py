"""Patch-job drafts and the rule-based approval route.

The approval route comes from fixed rules (SSVC, asset criticality, OT flag) plus thresholds an authorised person
may tighten or loosen within limits, never from the draft, so a generated job cannot lower its own approval level.
Drafts are built from templates; an AI drafting step can replace ``draft_job`` without touching routing.
"""

from __future__ import annotations

from datetime import date, timedelta

from .model import Asset, Finding, RootCause
from .rootcause import WINDOWS_PATCH

ROLE_LABEL = {"manager": "Manager", "vm_analyst": "VM analyst", "vertical_head": "Vertical head"}
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


def _window(as_of: date) -> str:
    sat = as_of + timedelta(days=(5 - as_of.weekday()) % 7 or 7)
    return f"{sat:%a %d %b %Y}, 22:00 to 02:00 IST"


def _is_windows(hosts: list[Asset]) -> bool:
    return sum("windows" in h.os.lower() for h in hosts) * 2 >= len(hosts)


def draft_job(rc: RootCause, hosts: list[Asset], findings: list[Finding], as_of: date) -> dict:
    """A patch-job draft: target hosts, change, playbook, pre-checks, rollback, window, rings."""
    pkgs = sorted({(f.package, f.fixed) for f in findings if f.package})
    names = [h.hostname for h in hosts]
    ring1 = names[:max(1, len(names) // 10)]
    win = _is_windows(hosts)
    d: dict = {"targets": names, "window": _window(as_of),
               "rings": [{"name": "Ring 1 (canary)", "hosts": ring1},
                         {"name": "Ring 2 (rest)", "hosts": [n for n in names if n not in ring1]}] if len(names) > 1
               else [{"name": "Single host", "hosts": names}],
               "changes": [f"Install {v}" if p == WINDOWS_PATCH else f"{p} → {v}" for p, v in pkgs]
               or [f.control or f.title for f in findings[:1]]}

    if rc.is_ot:
        shutdown = as_of + timedelta(days=24)
        d.update({
            "tool": "Staged plan, executed by a plant engineer",
            "summary": f"Apply OEM-approved updates to {len(names)} OT assets at the planned shutdown.",
            "playbook": "\n".join([
                "1. Request OEM approval for: " + "; ".join(d["changes"]),
                "2. Until the shutdown, keep the compensating control: IPS virtual-patch rule for "
                + ", ".join(sorted({c for f in findings for c in f.cves})[:4]) + " on the cell firewall, "
                "and allow engineering access only through the remote-access broker",
                "3. Back up project files, firmware and HMI images; record logic checksums",
                f"4. At the {shutdown:%d %b %Y} shutdown, apply the update to one asset, run functional checks with "
                "operations, then the rest",
                "5. Verify with the passive OT monitor and a safe rescan; Sutra closes findings only on that proof",
            ]),
            "prechecks": ["OEM approval received", "Shutdown slot confirmed with operations",
                          "Backups of firmware, logic and HMI images verified", "Rollback media on site"],
            "rollback": "Restore the backed-up firmware and project files; compare logic checksums with the record.",
            "window": f"Planned shutdown {shutdown:%a %d %b %Y}",
            "oem_approval": "Pending",
            "compensating_control": "IPS virtual patch on the cell firewall, broker-only remote access",
        })
    elif rc.kind == "base-image":
        d.update({
            "tool": "Image pipeline (Packer) and " + ("Intune / SCCM" if win else "Ansible"),
            "summary": f"Rebuild {rc.key} with fixed packages, then patch the {len(names)} running hosts in rings.",
            "playbook": ("# packer: build " + rc.key + "-next\n" +
                         "\n".join(f"#  - update {p} to {v}" for p, v in pkgs) +
                         ("\n# then deploy the same updates to running hosts with Intune (rings below)" if win else
                          "\n- hosts: ring1:ring2\n  serial: \"20%\"\n  tasks:\n" +
                          "\n".join(f"    - ansible.builtin.dnf: {{ name: \"{p}-{v}\", state: present }}"
                                    for p, v in pkgs) +
                          "\n    - ansible.builtin.reboot: { reboot_timeout: 900 }")),
            "prechecks": ["VM snapshot of ring 1", "Image build passes CIS and Sutra scan",
                          "Service health baseline captured"],
            "rollback": "Revert ring hosts to snapshot; keep the previous image version as the template.",
        })
    elif rc.kind in ("config-template", "fleet-config"):
        tpl = rc.key.split("|")[0] if rc.kind == "config-template" else "per-host configuration"
        d.update({
            "tool": "Group Policy" if win else "Ansible role",
            "summary": f"Change {tpl} once and re-apply to {len(names)} hosts.",
            "playbook": f"# {tpl}\n# {rc.fix}\n# re-apply: " + ("gpupdate /force on targets" if win else
                                                               "ansible-playbook site.yml --limit targets"),
            "prechecks": ["Confirm no legacy client still needs the old setting", "Change ticket raised"],
            "rollback": f"Restore the previous version of {tpl}.",
        })
    elif rc.kind == "shared-credential":
        d.update({
            "tool": "Windows LAPS / password vault",
            "summary": f"Give each of the {len(names)} hosts its own credential and retire the shared one.",
            "playbook": "1. Enrol targets in Windows LAPS (or the vault)\n2. Rotate the shared account on every host\n"
                        "3. Disable the account where it is unused\n4. Rescan to prove the old credential fails",
            "prechecks": ["Find services and scripts that use the shared credential", "Vault access for operators"],
            "rollback": "Vault keeps the previous secret for 24 hours.",
        })
    else:
        tool = "Intune / SCCM" if win else "Ansible"
        d.update({
            "tool": tool,
            "summary": f"Update {', '.join(p for p, _ in pkgs) or 'the affected software'} on {len(names)} hosts.",
            "playbook": ("# Intune app update\n" + "\n".join(f"#  {p}: require version >= {v}" for p, v in pkgs))
            if win else ("- hosts: targets\n  serial: \"20%\"\n  tasks:\n" + "\n".join(
                f"    - name: update {p}\n      # upgrade to {v} or later (vendor package)" for p, v in pkgs)),
            "prechecks": ["Snapshot or backup", "Application owner sign-off", "Service health baseline captured"],
            "rollback": "Reinstall the previous version from the software repository; restore snapshot if needed.",
        })
    return d
