from __future__ import annotations

import json
from datetime import date, datetime

import pytest
from conftest import at, audit, finding, generator, records

from sutra_compliance import (
    ActivityRecord,
    Asset,
    CompensatingControl,
    Entity,
    EntityRecords,
    EntityStatus,
    Incident,
    assess_applicability,
    check_change,
    evaluate_entity,
)

ALL_ACTIVITIES = ("self_audit", "policy_review", "ccmp_drill", "ir_plan_review", "asset_register_review")


def healthy(**kw):
    acts = tuple(ActivityRecord(a, date(2027, 4, 10), evidence_ids=()) for a in ALL_ACTIVITIES)
    kw.setdefault("audits", (audit(),))
    kw.setdefault("activities", acts)
    return records(**kw)


# ---------------------------------------------------------------- applicability


@pytest.mark.parametrize("etype, mw, covered", [
    ("generator", 600, True), ("generator", 50, True), ("generator", 49.9, False), ("captive_plant", 10, False),
    ("energy_storage", 75, True), ("transmission_licensee", None, True), ("sldc", None, True),
    ("power_exchange", None, True), ("vendor", None, True),
])
def test_applicability(pack, etype, mw, covered):
    assert assess_applicability(Entity("e", "E", etype, mw), pack).covered is covered


def test_capacity_needed_for_generators(pack):
    r = assess_applicability(Entity("e", "E", "generator", None), pack)
    assert r.covered is False and "not recorded" in r.reason


def test_below_threshold_mentions_cert_in_baseline(pack):
    assert "CERT-In" in assess_applicability(Entity("e", "E", "generator", 20), pack).reason


def test_markets_exclude_ot_and_vendor_chapters(pack):
    r = assess_applicability(Entity("e", "E", "power_exchange"), pack)
    assert set(r.excluded_topics) == {"ot", "vendor"}
    assert r.citation.rule_id == "APPL-MARKETS"


def test_vendor_scope_flagged_undetermined(pack):
    res = evaluate_entity(records(entity=Entity("v", "OEM", "vendor")), pack, at(2027, 6, 1))
    assert res.applicability.chapters_determined is False
    assert any(u.startswith("Applicability:") for u in res.unchecked)


def test_not_covered_entity(pack):
    res = evaluate_entity(records(entity=generator(10)), pack, at(2027, 6, 1))
    assert res.status is EntityStatus.NOT_COVERED


def test_unknown_entity_type_rejected():
    with pytest.raises(ValueError):
        Entity("e", "E", "nuclear_plant")


# ---------------------------------------------------------------- Second Schedule


def test_second_schedule(pack):
    r = check_change(["third_party_integration", "ui_tweak"], pack)
    assert r.needs_pre_deployment_audit is True
    assert r.matched_categories == ("third_party_integration",)
    assert r.unknown_categories == ("ui_tweak",)
    assert r.citations[0].rule_id == "CEA-SECOND-SCHEDULE"
    assert check_change([], pack).needs_pre_deployment_audit is False


# ---------------------------------------------------------------- whole entity


def test_on_track(pack):
    res = evaluate_entity(healthy(findings=(finding(severity="medium"),)), pack, at(2027, 6, 1))
    assert res.regulation_in_force is True
    assert res.status is EntityStatus.ON_TRACK, [i.message for i in res.issues]
    assert res.finding_counts["open"] == 1


def test_uncompensated_overdue_finding_is_non_compliant(pack):
    res = evaluate_entity(healthy(findings=(finding(),)), pack, at(2027, 6, 15))
    assert res.status is EntityStatus.NON_COMPLIANT
    breach = next(i for i in res.issues if i.severity == "breach")
    assert breach.subject == "finding" and breach.rule_id == "CEA-COMPENSATING-CONTROLS"


def test_compensated_overdue_finding_needs_attention(pack):
    ctl = CompensatingControl("C1", "Isolated from corp network", date(2027, 6, 5))
    res = evaluate_entity(healthy(findings=(finding(compensating_controls=(ctl,)),)), pack, at(2027, 6, 15))
    assert res.status is EntityStatus.ATTENTION
    assert res.finding_counts["overdue_compensated"] == 1


def test_finding_due_soon_needs_attention(pack):
    res = evaluate_entity(healthy(findings=(finding(),)), pack, at(2027, 6, 1))
    assert res.status is EntityStatus.ATTENTION
    assert res.upcoming_deadlines[0].ref == "F1" and res.upcoming_deadlines[0].days_left == 9


def test_readiness_before_in_force(pack):
    early = records(audits=(audit(started=date(2026, 12, 1)),), findings=(finding(),))
    res = evaluate_entity(early, pack, at(2027, 3, 1))
    assert res.regulation_in_force is False
    assert res.status is EntityStatus.ON_TRACK
    assert res.status_if_in_force is EntityStatus.NON_COMPLIANT


def test_overdue_incident_report(pack):
    inc = Incident("I1", "ent-1", "x", at(2027, 6, 1, 10))
    res = evaluate_entity(healthy(incidents=(inc,)), pack, at(2027, 6, 1, 20))
    assert res.status is EntityStatus.NON_COMPLIANT
    assert {i.rule_id for i in res.issues if i.severity == "breach"} == {"CEA-INCIDENT-6H"}


def test_ineligible_auditor(pack):
    res = evaluate_entity(healthy(audits=(audit(status="other"),)), pack, at(2027, 6, 1))
    assert any(i.rule_id == "CEA-AUDITOR-ELIGIBILITY" and i.severity == "breach" for i in res.issues)


def test_disabled_rules_listed_as_unchecked(pack):
    res = evaluate_entity(healthy(), pack, at(2027, 6, 1))
    assert any(u.startswith("CEA-AUDITOR-ROTATION") for u in res.unchecked)


def test_market_entity_skips_excluded_topics(load_modified):
    # Tag one periodic rule as OT to prove excluded topics are filtered for exchanges.
    tagged = load_modified('topic = "data"', 'topic = "ot"')
    exch = Entity("x", "Exchange", "power_exchange")
    recs = EntityRecords(entity=exch, assets=(Asset("SRV-1", critical=True),))
    res = evaluate_entity(recs, tagged, at(2027, 6, 1))
    assert not any(i.rule_id == "CEA-BACKUP-AGE" for i in res.issues)
    res_gen = evaluate_entity(EntityRecords(entity=generator(), assets=(Asset("SRV-1", critical=True),)), tagged,
                              at(2027, 6, 1))
    assert any(i.rule_id == "CEA-BACKUP-AGE" for i in res_gen.issues)


def test_result_is_json_serialisable(pack):
    res = evaluate_entity(healthy(findings=(finding(),)), pack, at(2027, 6, 15))
    data = json.loads(json.dumps(res.to_dict()))
    assert data["status"] == "non_compliant"
    assert data["audits"][0]["findings"][0]["citations"][0]["rule_id"] == "CEA-FIX-CRITICAL-HIGH"


def test_records_validation():
    with pytest.raises(ValueError, match="unknown audit"):
        records(findings=(finding(audit_id="NOPE"),))
    with pytest.raises(ValueError, match="duplicate finding"):
        records(audits=(audit(),), findings=(finding(), finding()))
    with pytest.raises(ValueError, match="belongs to entity"):
        records(incidents=(Incident("I1", "other", "x", at(2027, 6, 1)),))


def test_naive_now_rejected(pack):
    with pytest.raises(ValueError):
        evaluate_entity(healthy(), pack, datetime(2027, 6, 1))
