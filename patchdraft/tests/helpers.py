"""Shared builders: small estates in the shape the scanners and CMDB produce, and a fake Claude client."""

from __future__ import annotations

import json
from datetime import date
from types import SimpleNamespace

from sutra_patchdraft import DraftInput, FindingInput, HostInput, MaintenancePolicy, RootCauseInput

AS_OF = date(2026, 10, 11)  # a Sunday

GLIBC_FIXED = "2.28-236.el8_9.7"
GLIBC_INSTALLED = "2.28-211.el8"


def rhel_glibc(n_hosts: int = 4, crown_jewel: str | None = "A1") -> DraftInput:
    hosts = tuple(HostInput(asset_id=f"A{i}", hostname=f"pun-app-rhel-{i:03d}", os="Red Hat Enterprise Linux 8.6",
                            zone="corp", site="Pune HQ", criticality=5 if f"A{i}" == crown_jewel else 3,
                            image="rhel8-base-2023q1", business_process="Billing")
                  for i in range(1, n_hosts + 1))
    findings = tuple(FindingInput(
        finding_id=f"FND-{i}", asset_id=f"A{i}", title="Red Hat Update for glibc (RHSA-2023:5455)",
        severity="high", kind="package", cves=("CVE-2023-4911",), package="glibc", installed=GLIBC_INSTALLED,
        fixed=GLIBC_FIXED, solution=f"Update glibc to {GLIBC_FIXED}", scanner_refs=("Qualys 242051",),
    ) for i in range(1, n_hosts + 1))
    rc = RootCauseInput(rc_id="RC-007", kind="package", key=f"glibc|{GLIBC_FIXED}",
                        title=f"glibc below {GLIBC_FIXED} on {n_hosts} hosts", fix=f"Upgrade glibc to {GLIBC_FIXED}.",
                        ssvc="Attend", cves=("CVE-2023-4911",))
    return DraftInput(root_cause=rc, hosts=hosts, findings=findings, as_of=AS_OF)


def ot_plc(n_hosts: int = 3, policy: MaintenancePolicy | None = None) -> DraftInput:
    hosts = tuple(HostInput(asset_id=f"P{i}", hostname=f"tpp-plc-s7-{i:02d}", os="Siemens S7-1500 firmware V2.9.4",
                            zone="ot-l1", site="Thermal plant", criticality=5, is_ot=True,
                            safety_critical=(i == 1), business_process="Generation")
                  for i in range(1, n_hosts + 1))
    findings = tuple(FindingInput(
        finding_id=f"OT-{i}", asset_id=f"P{i}",
        title="Siemens SIMATIC S7-1500 CPU firmware vulnerability (SSA-2026-0101)",
        severity="critical", kind="package", cves=("CVE-2024-12345",), package="S7-1500 CPU firmware",
        installed="V2.9.4", fixed="V3.1.0", solution="Update firmware to V3.1.0 per OEM guidance",
        scanner_refs=("Tenable plugin 501234",),
    ) for i in range(1, n_hosts + 1))
    rc = RootCauseInput(rc_id="RC-OT1", kind="base-image", key="s7-1500-fw", title="S7-1500 CPU firmware below V3.1.0",
                        fix="Staged plan: get OEM approval, apply at the next planned outage.", ssvc="Act", is_ot=True,
                        cves=("CVE-2024-12345",))
    return DraftInput(root_cause=rc, hosts=hosts, findings=findings, as_of=AS_OF,
                      policy=policy or MaintenancePolicy())


def valid_it_raw(n_hosts: int = 4) -> dict:
    """A model draft for ``rhel_glibc(n_hosts)`` that passes every check. Host refs follow sorted asset IDs."""
    refs = [f"H{i}" for i in range(1, n_hosts + 1)]
    return {
        "summary": f"Update glibc to {GLIBC_FIXED} with Ansible in two rings, canary first, then rescan.",
        "tool": "Ansible",
        "excluded_hosts": [],
        "rings": [
            {"name": "Canary", "hosts": [refs[1]], "purpose": "One non-critical billing host first"},
            {"name": "Rest", "hosts": [refs[0], *refs[2:]], "purpose": "Remaining hosts, including the crown jewel"},
        ],
        "steps": [
            {"action": "capture_health_baseline", "ring": 0, "changes": [], "detail": "Record billing health.",
             "cites": ["R1"]},
            {"action": "deploy_update", "ring": 1, "changes": ["C1"], "detail": "Run the dnf update.",
             "cites": ["F2", "H2"]},
            {"action": "verify_service_health", "ring": 1, "changes": [], "detail": "Compare with the baseline.",
             "cites": ["H2"]},
            {"action": "deploy_update", "ring": 2, "changes": ["C1"], "detail": "Same change on the rest.",
             "cites": ["F1"]},
            {"action": "rescan", "ring": 0, "changes": [], "detail": "Qualys rescan to close RHSA-2023:5455.",
             "cites": ["F1", "F2"]},
        ],
        "prechecks": [{"text": "Snapshot every host", "cites": ["R1"]}],
        "rollback": {"trigger": "Billing health check fails", "steps": [f"Downgrade glibc to {GLIBC_INSTALLED}"],
                     "cites": ["C1"]},
        "assumptions": [],
    }


def valid_ot_raw(n_hosts: int = 3) -> dict:
    refs = [f"H{i}" for i in range(1, n_hosts + 1)]
    return {
        "summary": "Staged firmware update to V3.1.0 at the shutdown, one PLC first.",
        "excluded_hosts": [],
        "rings": [{"name": "Stage 1", "hosts": [refs[1]], "purpose": "One non-safety PLC first"},
                  {"name": "Stage 2", "hosts": [refs[0], *refs[2:]], "purpose": "The rest"}],
        "steps": [
            {"action": "request_oem_approval", "ring": 0, "changes": [], "detail": "Ask Siemens to approve V3.1.0.",
             "cites": ["C1"]},
            {"action": "hold_compensating_control", "ring": 0, "changes": [], "detail": "Block S7 traffic from IT.",
             "cites": ["R1"]},
            {"action": "backup_configuration", "ring": 0, "changes": [], "detail": "Back up project files.",
             "cites": ["R1"]},
            {"action": "apply_update_manually", "ring": 1, "changes": ["C1"], "detail": "Engineer flashes firmware.",
             "cites": ["H2"]},
            {"action": "functional_check_with_operations", "ring": 1, "changes": [], "detail": "Check the loop.",
             "cites": ["H2"]},
            {"action": "apply_update_manually", "ring": 2, "changes": ["C1"], "detail": "Repeat on the rest.",
             "cites": ["H1"]},
            {"action": "verify_with_passive_monitor", "ring": 0, "changes": [], "detail": "Monitor shows V3.1.0.",
             "cites": ["F1"]},
        ],
        "prechecks": [{"text": "OEM approval in writing", "cites": ["R1"]}],
        "rollback": {"trigger": "Functional check fails", "steps": ["Restore firmware V2.9.4 from backup"],
                     "cites": ["R1"]},
        "assumptions": [],
        "oem_approval_request": {"changes": ["C1"], "detail": "Confirm V3.1.0 for these CPUs.", "cites": ["F1"]},
        "compensating_controls": [{"control": "Cell firewall blocks IT-to-PLC traffic", "hosts": refs,
                                   "cites": ["R1"]}],
    }


def response(payload, *, stop_reason="end_turn", model="claude-opus-5-5", blocks=None):
    text = payload if isinstance(payload, str) else json.dumps(payload)
    content = blocks if blocks is not None else [SimpleNamespace(type="thinking", thinking=""),
                                                 SimpleNamespace(type="text", text=text)]
    return SimpleNamespace(stop_reason=stop_reason, content=content, model=model, stop_details=None)


class FakeMessages:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class FakeClient:
    """Stands in for ``anthropic.Anthropic``: records each request and replays scripted replies."""

    def __init__(self, *outcomes):
        self.messages = FakeMessages(outcomes)
        self.beta = SimpleNamespace(messages=self.messages)

    @property
    def calls(self) -> list[dict]:
        return self.messages.calls
