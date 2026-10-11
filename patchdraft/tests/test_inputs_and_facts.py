from datetime import date, time
from types import SimpleNamespace

import pytest

from sutra_patchdraft import (
    DraftInput,
    FindingInput,
    HostInput,
    InputError,
    MaintenancePolicy,
    RootCauseInput,
    from_sutra,
)
from sutra_patchdraft.facts import WINDOWS_PATCH, build_facts, clean, corpus
from sutra_patchdraft.windows import it_windows, ot_window

from helpers import AS_OF, GLIBC_FIXED, ot_plc, rhel_glibc

RC = RootCauseInput(rc_id="RC-1", kind="single", key="k", title="t", fix="f")


def test_input_needs_hosts():
    with pytest.raises(InputError, match="at least one host"):
        DraftInput(root_cause=RC, hosts=(), findings=(), as_of=AS_OF)


def test_input_rejects_findings_on_unknown_hosts():
    host = HostInput(asset_id="A1", hostname="h1")
    finding = FindingInput(finding_id="F1", asset_id="A9", title="x", severity="high", kind="other")
    with pytest.raises(InputError, match="A9"):
        DraftInput(root_cause=RC, hosts=(host,), findings=(finding,), as_of=AS_OF)


def test_input_rejects_duplicate_hosts_and_unknown_ssvc():
    host = HostInput(asset_id="A1", hostname="h1")
    with pytest.raises(InputError, match="duplicate"):
        DraftInput(root_cause=RC, hosts=(host, host), findings=(), as_of=AS_OF)
    bad = RootCauseInput(rc_id="RC-2", kind="single", key="k", title="t", fix="f", ssvc="Urgent")
    with pytest.raises(InputError, match="SSVC"):
        DraftInput(root_cause=bad, hosts=(host,), findings=(), as_of=AS_OF)


def test_policy_bounds():
    with pytest.raises(InputError):
        MaintenancePolicy(weekday=7)
    with pytest.raises(InputError):
        MaintenancePolicy(duration_hours=0)


def test_one_ot_host_makes_the_job_ot():
    inp = rhel_glibc(2)
    assert not inp.is_ot
    mixed = DraftInput(root_cause=inp.root_cause, hosts=(*inp.hosts, HostInput("X", "hmi-01", is_ot=True)),
                       findings=inp.findings, as_of=AS_OF)
    assert mixed.is_ot


def test_from_sutra_reads_app_objects_and_leaves_evidence_out():
    src = SimpleNamespace(scanner="Qualys", scanner_ref="QID 242051", source_file="q.csv", source_row=4)
    rc = SimpleNamespace(rc_id="RC-9", kind="package", key="glibc|x", title="glibc", fix="Upgrade glibc",
                         ssvc="Act", is_ot=False, cves=["CVE-2023-4911"], asset_ids=["A1"])
    asset = SimpleNamespace(asset_id="A1", hostname="h1", ip="10.0.0.1", site="HQ", zone="dmz", os="RHEL 8",
                            owner="Billing", business_process="Billing", inr_per_hour=1.0, criticality=4, image="",
                            image_source="", config_template="", is_ot=False, safety_critical=False,
                            personal_data=True, in_cmdb=False, scanned_by={"qualys"})
    finding = SimpleNamespace(finding_id="FND-1", asset_id="A1", title="glibc", severity="high", cvss=7.8,
                              cves=["CVE-2023-4911"], port="0", kind="package", package="glibc", installed="1",
                              fixed="2", control="", credential_fp="", first_seen=None, last_seen=None,
                              evidence="password=hunter2", solution="Update", sources=[src, src])
    inp = from_sutra(rc, [asset], [finding], AS_OF)
    assert inp.root_cause.ssvc == "Act"
    assert inp.hosts[0].criticality == 4 and inp.hosts[0].in_cmdb is False
    assert inp.findings[0].scanner_refs == ("Qualys QID 242051",)
    assert "hunter2" not in repr(inp)


def test_facts_group_findings_into_changes():
    inp = rhel_glibc(3)
    facts = build_facts(inp)
    assert list(facts.hosts) == ["H1", "H2", "H3"]
    assert [h.asset_id for h in facts.hosts.values()] == ["A1", "A2", "A3"]
    (change,) = facts.changes.values()
    assert change.text == f"Update glibc to {GLIBC_FIXED} or later"
    assert change.host_refs == ("H1", "H2", "H3") and len(change.finding_refs) == 3


def test_change_wording_per_kind():
    hosts = (HostInput("A1", "w1", os="Windows Server 2019"),)
    findings = (
        FindingInput("F1", "A1", "Missing update", "high", "package", package=WINDOWS_PATCH, fixed="KB5034439"),
        FindingInput("F2", "A1", "SMBv1 enabled", "medium", "config", control="SMBv1 enabled"),
        FindingInput("F3", "A1", "Shared local admin", "high", "credential"),
        FindingInput("F4", "A1", "OpenSSL", "high", "package", package="openssl"),
    )
    facts = build_facts(DraftInput(root_cause=RC, hosts=hosts, findings=findings, as_of=AS_OF))
    texts = sorted(c.text for c in facts.changes.values())
    assert texts == ["Correct the setting: SMBv1 enabled", "Install KB5034439",
                     "Retire the shared credential: Shared local admin",
                     "Update openssl (the scan data names no fixed version)"]


def test_clean_strips_control_and_bidi_characters():
    assert clean("a\nb\x00c‮d​", 50) == "a b c d"
    assert clean("x" * 20, 10) == "x" * 9 + "…"


def test_corpus_holds_every_input_value():
    text = corpus(rhel_glibc(2))
    for value in (GLIBC_FIXED, "rhsa-2023:5455", "cve-2023-4911", "pun-app-rhel-001", "qualys 242051"):
        assert value in text


def test_it_windows_start_the_week_after_as_of():
    policy = MaintenancePolicy(weekday=5, start=time(22, 0), duration_hours=4)
    assert it_windows(policy, AS_OF, 2) == ["Sat 17 Oct 2026, 22:00 to 02:00 IST",
                                            "Sat 24 Oct 2026, 22:00 to 02:00 IST"]
    # A window on the as-of day itself is too soon to approve; the next one is used.
    assert it_windows(policy, date(2026, 10, 17), 1) == ["Sat 24 Oct 2026, 22:00 to 02:00 IST"]


def test_ot_window_only_when_a_future_shutdown_is_named():
    assert ot_window(MaintenancePolicy(), AS_OF) is None
    assert ot_window(MaintenancePolicy(ot_shutdown=date(2026, 10, 1)), AS_OF) is None
    assert ot_window(MaintenancePolicy(ot_shutdown=date(2026, 11, 7)), AS_OF) == "Planned shutdown Sat 07 Nov 2026"


def test_ot_fixture_is_ot():
    assert ot_plc().is_ot
