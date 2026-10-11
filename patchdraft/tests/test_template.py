from datetime import date

import pytest

from sutra_patchdraft import DraftInput, FindingInput, HostInput, MaintenancePolicy, RootCauseInput, template_only
from sutra_patchdraft.facts import WINDOWS_PATCH, build_facts, corpus
from sutra_patchdraft.grounding import validate
from sutra_patchdraft.schema import OT_TOOL
from sutra_patchdraft.template import template_raw

from helpers import AS_OF, GLIBC_FIXED, ot_plc, rhel_glibc

WIN = "Windows Server 2019 Datacenter"


def estate(kind, os_name, findings_kind, n=12, **finding_fields):
    hosts = tuple(HostInput(f"A{i:02d}", f"host-{i:02d}", os=os_name, criticality=(5 if i == 1 else 2),
                            config_template="GPO-Servers" if kind == "config-template" else "",
                            image="win2019-gold" if kind == "base-image" else "", in_cmdb=i != 3)
                  for i in range(1, n + 1))
    findings = tuple(FindingInput(f"F{i:02d}", f"A{i:02d}", "Finding title", "high", findings_kind, **finding_fields)
                     for i in range(1, n + 1))
    rc = RootCauseInput("RC-X", kind, "win2019-gold" if kind == "base-image" else "key", "Title", "Fix it")
    return DraftInput(root_cause=rc, hosts=hosts, findings=findings, as_of=AS_OF)


CASES = {
    "package-linux": (estate("package", "Ubuntu 22.04", "package", package="openssl", installed="3.0.2",
                             fixed="3.0.2-0ubuntu1.15"), "Ansible"),
    "package-windows-kb": (estate("package", WIN, "package", package=WINDOWS_PATCH, fixed="KB5034439"), "Intune"),
    "base-image": (estate("base-image", WIN, "package", package="curl", fixed="8.4.0"), "Image pipeline (Packer)"),
    "config-template": (estate("config-template", WIN, "config", control="SMBv1 enabled"), "Group Policy"),
    "fleet-config": (estate("fleet-config", "RHEL 9", "config", control="SSH root login allowed"), "Ansible"),
    "shared-credential": (estate("shared-credential", WIN, "credential"), "Windows LAPS / password vault"),
    "network-appliance": (estate("single", "FortiOS 7.2", "other", n=1, solution="Upgrade FortiOS"),
                          "Manual change by the owning team"),
    "no-fixed-version": (estate("package", "RHEL 9", "package", package="libxml2"), "Ansible"),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_every_template_draft_passes_the_same_checks_as_a_model_draft(name):
    inp, tool = CASES[name]
    facts = build_facts(inp)
    raw = template_raw(inp, facts, "it")
    assert validate(raw, "it", facts, corpus(inp)) == []
    draft = template_only().draft(inp)
    assert draft.source == "template" and draft.tool == tool and draft.executable
    assert sorted(draft.target_asset_ids) == sorted(h.asset_id for h in inp.hosts)


def test_template_canary_is_small_and_avoids_crown_jewels():
    draft = template_only().draft(CASES["package-linux"][0])
    canary, rest = draft.rings
    assert canary.asset_ids == ["A02"] and "A01" in rest.asset_ids
    assert canary.window == "Sat 17 Oct 2026, 22:00 to 02:00 IST"
    assert rest.window == "Sat 24 Oct 2026, 22:00 to 02:00 IST"


def test_template_says_what_it_does_not_know():
    draft = template_only().draft(CASES["no-fixed-version"][0])
    assert any("no fixed version for libxml2" in a for a in draft.assumptions)
    assert any("not in the asset register" in a for a in draft.assumptions)


def test_template_uses_only_input_versions():
    draft = template_only().draft(rhel_glibc())
    assert draft.changes[0]["text"] == f"Update glibc to {GLIBC_FIXED} or later"
    assert draft.fallback_reason == "AI drafting is switched off"


def test_ot_template_is_a_staged_human_run_plan():
    inp = ot_plc()
    draft = template_only().draft(inp)
    assert draft.lane == "ot" and not draft.executable and draft.tool == OT_TOOL
    assert draft.oem_approval == "Pending" and draft.compensating_controls
    assert draft.rings[0].asset_ids == ["P2"]  # one non-safety asset first
    assert {s.action for s in draft.steps} >= {"request_oem_approval", "backup_configuration",
                                               "apply_update_manually", "functional_check_with_operations"}
    assert draft.window.startswith("Shutdown slot not set")
    assert any("No planned shutdown date" in a for a in draft.assumptions)


def test_ot_template_uses_the_named_shutdown():
    draft = template_only().draft(ot_plc(policy=MaintenancePolicy(ot_shutdown=date(2026, 11, 7))))
    assert draft.window == "Planned shutdown Sat 07 Nov 2026"
    assert all(r.window == draft.window for r in draft.rings)


def test_legacy_dict_matches_the_app_screen_keys():
    it = template_only().draft(rhel_glibc()).to_legacy_dict()
    assert {"targets", "window", "rings", "changes", "tool", "summary", "playbook", "prechecks",
            "rollback"} <= set(it)
    ot = template_only().draft(ot_plc()).to_legacy_dict()
    assert {"oem_approval", "compensating_control"} <= set(ot)
    assert "Ansible" not in ot["playbook"]
