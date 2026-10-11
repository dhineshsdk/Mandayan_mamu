"""Patch management: ownership, patch-job drafts, criticality-based approval routing and the audit trail.

The approval route comes from fixed rules (SSVC, asset criticality, OT flag), never from the draft, so a generated
job cannot lower its own approval level. Drafts are built from templates in this prototype; an AI drafting step
can replace ``draft_job`` without touching the routing or the workflow.
"""

from __future__ import annotations

import json
import threading
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from .model import Asset, Finding, RootCause
from .rootcause import WINDOWS_PATCH

ROLE_LABEL = {"manager": "Manager", "vm_analyst": "VM analyst", "vertical_head": "Vertical head"}
UNOWNED = "(no owner)"


def org_for(assets: dict[str, Asset], chart: dict | None) -> dict:
    """Ownership chart for every team that owns an asset; teams missing from the chart get placeholders."""
    chart = chart or {"teams": {}, "vm_analyst": "VM analyst"}
    teams = dict(chart["teams"])
    for a in assets.values():
        t = a.owner or UNOWNED
        if t not in teams:
            teams[t] = {"team": t, "jira": "", "manager": "", "vertical": "Unassigned", "vertical_head": ""}
    return {"teams": teams, "vm_analyst": chart.get("vm_analyst", "VM analyst")}


def team_of(asset: Asset) -> str:
    return asset.owner or UNOWNED


def route(rc: RootCause, hosts: list[Asset]) -> dict:
    """Who must approve, from the chain in the product map (section 4b)."""
    crown = any(h.criticality >= 5 for h in hosts)
    if rc.is_ot:
        return {"steps": ["manager", "vm_analyst", "vertical_head"], "type": "staged-plan", "emergency": False,
                "reason": "OT asset: staged plan executed by a plant engineer, with OEM approval and a shutdown slot"}
    if rc.ssvc == "Act":
        return {"steps": ["manager", "vm_analyst", "vertical_head"], "type": "patch-job", "emergency": True,
                "reason": "SSVC Act: actively exploited; the vertical head can fast-track it as an emergency change"}
    if rc.ssvc in ("Attend", "Track*") or crown:
        why = f"SSVC {rc.ssvc}" if rc.ssvc in ("Attend", "Track*") else "crown-jewel asset"
        return {"steps": ["manager", "vm_analyst", "vertical_head"], "type": "patch-job", "emergency": False,
                "reason": f"{why}: needs the vertical head"}
    return {"steps": ["manager", "vm_analyst"], "type": "patch-job", "emergency": False,
            "reason": "SSVC Track on non-critical IT assets: manager and VM analyst are enough"}


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
                f"3. Back up project files, firmware and HMI images; record logic checksums",
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


class JobStore:
    """Patch jobs for the loaded dataset, kept in a JSON file in the workspace."""

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.jobs: list[dict] = json.loads(path.read_text()) if path.exists() else []

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.jobs, indent=1))

    def _audit(self, job, actor, action, comment=""):
        job["audit"].append({"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "actor": actor,
                             "action": action, "comment": comment})

    def get(self, job_id: str) -> dict:
        for j in self.jobs:
            if j["id"] == job_id:
                return j
        raise KeyError(f"no job {job_id}")

    def create(self, rc: RootCause, team: str, org: dict, assets: dict[str, Asset], findings: dict[str, Finding],
               as_of: date, mode: str, actor: str, ticket: str = "") -> dict:
        hosts = [assets[a] for a in rc.asset_ids if team_of(assets[a]) == team]
        if not hosts:
            raise ValueError(f"{team} owns no hosts in {rc.rc_id}")
        mine = [findings[f] for f in rc.finding_ids if team_of(assets[findings[f].asset_id]) == team]
        t = org["teams"].get(team, {})
        with self.lock:
            for j in self.jobs:
                if j["rc_id"] == rc.rc_id and j["team"] == team and j["status"] in (
                        "pending", "approved", "fixing-manually"):
                    raise ValueError(f"{team} already has {j['id']} open for {rc.rc_id}")
            n = len(self.jobs) + 1
            job = {"id": f"J-{n:03d}", "rc_id": rc.rc_id, "rc_title": rc.title, "team": team, "mode": mode,
                   "jira": f"{t.get('jira') or 'SEC'}-{100 + n}", "created": as_of.isoformat(),
                   "hosts": [h.asset_id for h in hosts], "findings": [f.finding_id for f in mine],
                   "ssvc": rc.ssvc, "is_ot": rc.is_ot, "audit": []}
            if mode == "manual":
                job.update({"status": "fixing-manually", "ticket": ticket, "route": None, "steps": [],
                            "draft": None})
                self._audit(job, actor, "Marked as fixing manually", f"Change ticket {ticket}" if ticket else "")
            else:
                r = route(rc, hosts)
                approvers = {"manager": t.get("manager") or "Team manager", "vm_analyst": org["vm_analyst"],
                             "vertical_head": t.get("vertical_head") or "Vertical head"}
                job.update({"status": "pending", "route": r, "draft": draft_job(rc, hosts, mine, as_of),
                            "steps": [{"role": s, "label": ROLE_LABEL[s], "who": approvers[s], "state": "waiting",
                                       "comment": "", "at": None} for s in r["steps"]]})
                job["steps"][0]["state"] = "current"
                self._audit(job, actor, "Raised " + ("staged plan" if rc.is_ot else "patch job"),
                            r["reason"])
            self.jobs.append(job)
            self._save()
            return job

    def decide(self, job_id: str, action: str, actor: str, comment: str = "") -> dict:
        with self.lock:
            job = self.get(job_id)
            step = next((s for s in job["steps"] if s["state"] == "current"), None)
            if job["status"] != "pending" or step is None:
                raise ValueError(f"{job_id} is not waiting for an approval")
            if actor != step["who"]:
                raise ValueError(f"{job_id} is waiting for {step['who']}, not {actor}")
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            step.update({"comment": comment, "at": now})
            if action == "approve":
                step["state"] = "approved"
                nxt = next((s for s in job["steps"] if s["state"] == "waiting"), None)
                if nxt:
                    nxt["state"] = "current"
                else:
                    job["status"] = "approved"
                verb = "Approved" + (" as emergency change" if job["route"]["emergency"] and
                                     step["role"] == "vertical_head" else "")
            elif action == "reject":
                step["state"], job["status"], verb = "rejected", "rejected", "Rejected"
            elif action == "sendback":
                step["state"], job["status"], verb = "sent-back", "sent-back", "Sent back to the team"
            else:
                raise ValueError(f"unknown action {action}")
            self._audit(job, actor, f"{verb} ({step['label']})", comment)
            self._save()
            return job
