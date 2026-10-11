from __future__ import annotations

import tomllib
from datetime import date

import pytest
from conftest import BUNDLED

from sutra_compliance import RulePackError, load_rule_pack, parse_rule_pack
from sutra_compliance.rulepack import FixDeadlineRule


def test_bundled_pack_loads_with_metadata(pack):
    assert pack.id == "cea-cs-2026"
    assert pack.in_force_from == date(2027, 4, 1)
    assert pack.utc_offset_minutes == 330
    assert pack.version


def test_every_rule_cites_known_sources_and_is_marked_unverified(pack):
    """Nothing in the bundled pack has been read against the gazette, and it must say so."""
    assert pack.verification == "unverified_against_gazette"
    for rule in [*pack.rules, *pack.applicability]:
        assert rule.sources, rule.id
        assert all(s in pack.sources for s in rule.sources), rule.id
        assert rule.verification == "unverified_against_gazette", rule.id
        assert rule.gazette_clause == "", rule.id
    assert pack.sources["cea-gazette"].read is False


def test_fix_windows_match_the_research_note(pack):
    crit = pack.fix_rule_for("critical")
    assert pack.fix_rule_for("high") is crit
    assert crit.duration.months == 1 and crit.anchor == "audit_report_submitted"
    med = pack.fix_rule_for("medium")
    assert pack.fix_rule_for("low") is med
    assert med.duration.months == 3
    assert pack.fix_rule_for("info") is None


def test_conflicting_rotation_rule_is_not_enforced(pack):
    rotation = pack.rule("CEA-AUDITOR-ROTATION")
    assert rotation.enabled is False
    assert rotation.confidence == "conflicting"
    assert len(rotation.variants) == 3


def test_single_source_rules_say_so(pack):
    assert pack.rule("CEA-COMPENSATING-CONTROLS").confidence == "single_source"
    assert pack.rule("CEA-PRIOR-FINDINGS").confidence == "single_source"


def test_citation_carries_pack_version_and_sources(pack):
    c = pack.cite(pack.rule("CEA-FIX-CRITICAL-HIGH")).to_dict()
    assert c["pack_version"] == pack.version
    assert c["verification"] == "unverified_against_gazette"
    assert c["gazette_clause"] is None
    assert {s["id"] for s in c["sources"]} == {"research-note", "beacon", "cea-gazette"}


def test_summary_lists_unverified_and_disabled_rules(pack):
    s = pack.summary()
    assert len(s["unverified_rules"]) == len(pack.rules)
    assert s["disabled_rules"] == ["CEA-AUDITOR-ROTATION"]


def test_deferred_obligations_recorded(pack):
    assert pack.deferred[0].clauses == ("5(9)", "5(24)", "5(33)", "5(39)", "6(2)", "6(7)")


# ---------------------------------------------------------------- correcting the data


def test_correcting_a_window_changes_the_rule(load_modified):
    fixed = load_modified('duration = { months = 1 }', 'duration = { days = 30 }')
    rule = fixed.fix_rule_for("critical")
    assert isinstance(rule, FixDeadlineRule)
    assert rule.duration.after(date(2027, 1, 31)) == date(2027, 3, 2)


def _raw():
    return tomllib.loads(BUNDLED.read_text(encoding="utf-8"))


def _rule(data, rule_id):
    return next(r for r in data["rules"] if r["id"] == rule_id)


def test_verified_rule_with_clause_and_gazette_loads():
    data = _raw()
    r = _rule(data, "CEA-FIX-CRITICAL-HIGH")
    r["verification"] = "verified_against_gazette"
    r["gazette_clause"] = "Reg X(1)"
    pack = parse_rule_pack(data)
    assert pack.cite(pack.rule("CEA-FIX-CRITICAL-HIGH")).gazette_clause == "Reg X(1)"


def test_verified_without_clause_rejected():
    data = _raw()
    _rule(data, "CEA-FIX-CRITICAL-HIGH")["verification"] = "verified_against_gazette"
    with pytest.raises(RulePackError) as err:
        parse_rule_pack(data)
    assert any("needs gazette_clause" in p for p in err.value.problems)


def test_pack_cannot_claim_verified_while_rules_are_not():
    data = _raw()
    data["pack"]["verification"] = "verified_against_gazette"
    with pytest.raises(RulePackError, match="marked verified"):
        parse_rule_pack(data)


def test_unknown_source_rejected():
    data = _raw()
    _rule(data, "CEA-INCIDENT-6H")["sources"].append("made-up-blog")
    with pytest.raises(RulePackError, match="unknown source 'made-up-blog'"):
        parse_rule_pack(data)


def test_rule_without_sources_rejected():
    data = _raw()
    _rule(data, "CEA-INCIDENT-6H")["sources"] = []
    with pytest.raises(RulePackError, match="'sources' must not be empty"):
        parse_rule_pack(data)


def test_overlapping_severity_rejected():
    data = _raw()
    _rule(data, "CEA-FIX-MEDIUM-LOW")["severities"] = ["medium", "low", "high"]
    with pytest.raises(RulePackError, match="'high' is covered by both"):
        parse_rule_pack(data)


def test_unknown_keys_and_bad_values_all_reported_together():
    data = _raw()
    _rule(data, "CEA-FIX-CRITICAL-HIGH")["duraton"] = {"months": 1}
    _rule(data, "CEA-FIX-MEDIUM-LOW")["duration"] = {"fortnights": 2}
    _rule(data, "CEA-INCIDENT-6H")["recipients"] = ["csirt_power", "interpol"]
    with pytest.raises(RulePackError) as err:
        parse_rule_pack(data)
    text = "\n".join(err.value.problems)
    assert "unknown key(s) ['duraton']" in text
    assert "fortnights" in text
    assert "interpol" in text


def test_enabling_rotation_requires_a_limit():
    data = _raw()
    _rule(data, "CEA-AUDITOR-ROTATION")["enabled"] = True
    with pytest.raises(RulePackError, match="max_consecutive > 0"):
        parse_rule_pack(data)


def test_bad_toml_reported(tmp_path):
    path = tmp_path / "broken.toml"
    path.write_text("[pack\n", encoding="utf-8")
    with pytest.raises(RulePackError, match="not valid TOML"):
        load_rule_pack(path)


def test_entity_type_in_two_applicability_entries_rejected():
    data = _raw()
    data["applicability"][1]["entity_types"].append("generator")
    with pytest.raises(RulePackError, match="'generator' appears in both"):
        parse_rule_pack(data)
