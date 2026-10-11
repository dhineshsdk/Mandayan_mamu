"""The template drafter: a rule-built draft for when AI drafting is off, unavailable or fails its checks.

It produces the same raw shape a model does and goes through the same validation and rendering, so every draft that
reaches a person, whatever its source, meets the same rules. All text is either fixed wording or values from the
fact table; nothing here knows a version or advisory that the scan did not report.
"""

from __future__ import annotations

from .facts import ROOT_CAUSE_REF, Facts, clean
from .inputs import DraftInput, HostInput

_LINUX = ("linux", "red hat", "rhel", "ubuntu", "debian", "centos", "suse", "rocky", "alma")


def _platform(hosts: list[HostInput]) -> str:
    """"windows", "linux" or "other", by majority of hosts."""
    win = sum("windows" in h.os.lower() for h in hosts)
    nix = sum(any(k in h.os.lower() for k in _LINUX) for h in hosts)
    if win * 2 >= len(hosts) and win:
        return "windows"
    if nix * 2 >= len(hosts) and nix:
        return "linux"
    return "other"


def _tool(kind: str, platform: str) -> str:
    if kind == "shared-credential":
        return "Windows LAPS / password vault"
    if kind == "base-image" and platform != "other":
        return "Image pipeline (Packer)"
    if platform == "other":
        return "Manual change by the owning team"
    if kind in ("config-template", "fleet-config"):
        return "Group Policy" if platform == "windows" else "Ansible"
    return "Intune" if platform == "windows" else "Ansible"


def _order(facts: Facts) -> list[str]:
    """Host refs, safest canaries first: lower criticality, no safety impact."""
    return sorted(facts.hosts, key=lambda r: (facts.hosts[r].criticality, facts.hosts[r].safety_critical,
                                              int(r[1:])))


def _split(order: list[str], first_size: int) -> list[list[str]]:
    if len(order) == 1:
        return [order]
    return [order[:first_size], order[first_size:]]


def _apply_verb(kind: str, lane: str) -> str:
    if lane == "ot":
        return "apply_update_manually"
    return {"config": "apply_config_change", "credential": "rotate_credential"}.get(kind, "deploy_update")


def _common_assumptions(inp: DraftInput, facts: Facts) -> list[str]:
    out = []
    for c in facts.changes.values():
        if c.kind == "package" and not c.fixed:
            out.append(f"The scan data names no fixed version for {c.package}; confirm the target version with "
                       "the vendor before approval.")
    unregistered = [h for h in facts.hosts.values() if not h.in_cmdb]
    if unregistered:
        out.append(f"{len(unregistered)} host(s) are not in the asset register; confirm their owner and build "
                   "before the change.")
    return out


def template_raw(inp: DraftInput, facts: Facts, lane: str) -> dict:
    rc = inp.root_cause
    order = _order(facts)
    hosts = list(facts.hosts.values())
    all_changes = list(facts.changes)
    steps: list[dict] = []

    def step(action: str, ring: int, detail: str, changes: list[str] | None = None,
             cites: list[str] | None = None) -> None:
        steps.append({"action": action, "ring": ring, "changes": changes or [], "detail": detail,
                      "cites": cites or [ROOT_CAUSE_REF]})

    def ring_changes(ring_hosts: list[str], kinds: set[str] | None = None) -> list[str]:
        members = set(ring_hosts)
        return [c for c, ch in facts.changes.items()
                if members & set(ch.host_refs) and (kinds is None or ch.kind in kinds)]

    if lane == "ot":
        groups = _split(order, 1)
        names = ["Stage 1 (first asset)", "Stage 2 (remaining assets)"] if len(groups) > 1 else ["Single stage"]
        purposes = ["Apply to one asset and prove it with operations before touching the rest",
                    "Apply to the remaining assets once stage 1 passes its checks"][:len(groups)]
        if len(groups) == 1:
            purposes = ["Apply to the only affected asset"]
        step("request_oem_approval", 0, "Send the OEM the change list and ask it to confirm the changes for the "
             "installed firmware and project versions.", cites=[ROOT_CAUSE_REF, *all_changes])
        step("hold_compensating_control", 0, "Until the shutdown, restrict network access to these assets at the "
             "cell or zone firewall and allow engineering access only through the remote-access broker.")
        step("confirm_shutdown_slot", 0, "Agree the shutdown slot and the operations contact who will witness "
             "the checks.")
        step("backup_configuration", 0, "Back up project files, firmware and HMI images, and record logic "
             "checksums.")
        for i, group in enumerate(groups, 1):
            step("apply_update_manually", i, "The plant engineer applies the OEM-approved change following the "
                 "OEM procedure.", changes=ring_changes(group), cites=[*group])
            step("functional_check_with_operations", i, "Run the functional checks with operations before "
                 "moving on.", cites=[*group])
        step("verify_with_passive_monitor", 0, "Confirm with the passive OT monitor that the assets report the "
             "changed versions and normal traffic.")
        step("safe_rescan", 0, "Run a safe rescan; Sutra closes the findings only on that proof.",
             cites=[ROOT_CAUSE_REF, *list(facts.findings)[:20]])
        raw = {
            "summary": f"Staged plan for {len(hosts)} OT asset(s): OEM approval, compensating control until the "
                       "shutdown, then a hand-applied change one asset first.",
            "excluded_hosts": [],
            "rings": [{"name": n, "hosts": g, "purpose": p} for n, g, p in zip(names, groups, purposes, strict=True)],
            "steps": steps,
            "prechecks": [{"text": t, "cites": [ROOT_CAUSE_REF]} for t in (
                "OEM approval received in writing", "Shutdown slot confirmed with operations",
                "Backups of firmware, logic and HMI images verified", "Rollback media on site")],
            "rollback": {"trigger": "A functional check fails or the process does not return to normal operation.",
                         "steps": ["Restore the backed-up firmware, logic and HMI images.",
                                   "Compare logic checksums with the recorded values.",
                                   "Keep the compensating control in place and report back to the OEM."],
                         "cites": [ROOT_CAUSE_REF]},
            "assumptions": _common_assumptions(inp, facts) + [
                "The compensating control must be confirmed with the plant's OT security owner."],
            "oem_approval_request": {"changes": all_changes, "detail": "Confirm the changes are approved for the "
                                     "installed firmware and project versions, with the OEM procedure to follow.",
                                     "cites": [ROOT_CAUSE_REF]},
            "compensating_controls": [{"control": "Firewall restriction at the cell or zone boundary and "
                                       "broker-only remote access", "hosts": order, "cites": [ROOT_CAUSE_REF]}],
        }
        return raw

    platform = _platform(hosts)
    tool = _tool(rc.kind, platform)
    groups = _split(order, max(1, len(order) // 10))
    names = ["Ring 1 (canary)", "Ring 2 (rest)"] if len(groups) > 1 else ["Single host"]
    purposes = (["Lowest-criticality hosts first, to catch a bad change early",
                 "Remaining hosts once the canary is healthy"] if len(groups) > 1 else ["The only affected host"])
    step("capture_health_baseline", 0, "Record service health on every target so the change can be compared "
         "against it.")
    step("snapshot", 0, "Take a VM snapshot or backup of each target before the change.")
    if rc.kind == "base-image":
        image_changes = [c for c, ch in facts.changes.items() if ch.kind in ("package", "windows-update")]
        if image_changes:
            step("rebuild_image", 0, f"Rebuild the image {clean(rc.key, 120)} with the changes and keep the "
                 "previous version as a fallback template.", changes=image_changes)
    for i, group in enumerate(groups, 1):
        for kinds in ({"package", "windows-update", "other"}, {"config"}, {"credential"}):
            changes = ring_changes(group, kinds)
            if changes:
                verb = _apply_verb(facts.changes[changes[0]].kind, lane)
                step(verb, i, f"Apply with {tool} to the hosts in this ring.", changes=changes, cites=[*group])
        step("verify_service_health", i, "Compare service health with the baseline before the next ring.",
             cites=[*group])
    step("rescan", 0, "Rescan the targets; Sutra closes the findings only when the rescan proves the fix.",
         cites=[ROOT_CAUSE_REF, *list(facts.findings)[:20]])

    prechecks = {
        "base-image": ["Image build passes the hardening baseline and a Sutra scan", "VM snapshot of ring 1"],
        "config-template": ["No legacy client still needs the old setting", "Change ticket raised"],
        "fleet-config": ["No legacy client still needs the old setting", "Change ticket raised"],
        "shared-credential": ["Services and scripts that use the shared credential are found and listed",
                              "Vault access for operators confirmed"],
    }.get(rc.kind, ["Snapshot or backup taken", "Application owner sign-off"])
    rollback = {
        "base-image": ["Revert ring hosts to their snapshots.", "Keep the previous image version as the template."],
        "config-template": ["Restore the previous version of the template and re-apply it."],
        "fleet-config": ["Restore the previous setting on the affected hosts."],
        "shared-credential": ["Restore the previous secret from the vault for the affected service."],
    }.get(rc.kind, ["Reinstall the previous version from the software repository.",
                    "Restore the snapshot if the service does not recover."])
    return {
        "summary": f"{tool}: apply {len(facts.changes)} change(s) to {len(hosts)} host(s) in "
                   f"{len(groups)} ring(s), then rescan.",
        "tool": tool,
        "excluded_hosts": [],
        "rings": [{"name": n, "hosts": g, "purpose": p} for n, g, p in zip(names, groups, purposes, strict=True)],
        "steps": steps,
        "prechecks": [{"text": t, "cites": [ROOT_CAUSE_REF]} for t in prechecks + ["Service health baseline "
                                                                                     "captured"]],
        "rollback": {"trigger": "Service health drops below the baseline or the application owner reports a "
                                "fault.", "steps": rollback, "cites": [ROOT_CAUSE_REF]},
        "assumptions": _common_assumptions(inp, facts),
    }
