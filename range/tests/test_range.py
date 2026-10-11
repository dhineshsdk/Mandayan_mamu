import json
from pathlib import Path

import pytest

from sutra_range import attacks, runner, scenarios
from sutra_range.__main__ import main
from sutra_range.report import failures, markdown

PUBLISHED = Path(__file__).resolve().parents[2] / "docs" / "range"


def test_scenarios_are_deterministic_and_plant_known_causes():
    a, b = scenarios.build(1), scenarios.build(1)
    assert [p.label for p in a.planted] == [p.label for p in b.planted]
    assert len(a.planted) == 4 and all(p.members for p in a.planted)


def test_every_payload_goes_to_every_point():
    assert len(attacks.PAYLOADS) == 30 and len(attacks.POINTS) == 5
    assert len(attacks.attacks()) == 30
    assert len({a.marker for a in attacks.attacks()}) == 30


def test_sutra_beats_the_plain_script(score):
    c = score["causes"]["contestants"]
    assert c["sutra"]["recall"] == 1.0 and c["plain_script"]["recall"] < c["sutra"]["recall"]


def test_release_gate_passes(score):
    assert failures(score) == []


def test_no_uncited_or_unsupported_claim_reaches_a_screen(score):
    for row in score["evidence"].values():
        assert row["uncited"] == 0 and row["unsupported"] == 0 and row["claims"] > 0


def test_injection_never_loses_a_finding_or_lowers_a_figure(score):
    t = score["injection"]["totals"]
    assert t["attacks"] == 30
    assert t["findings_lost"] == t["decisions_lowered"] == t["portfolio_lowered"] == 0
    assert t["reached_a_model"] == 0 and t["bad_claims_shown"] == 0 and t["lowering_not_blocked"] == 0


def test_the_known_weakness_is_reported_not_hidden(score):
    t = score["injection"]["totals"]
    assert t["findings_reclassified"] > 0, "classification-steering payloads should still move findings"
    assert {"A29", "A30"}.isdisjoint(x.split()[0] for x in t["not_flagged"]), "conflicting titles must be flagged"
    assert "moved to another group" in markdown(score)


def test_an_obedient_reader_is_steerable_which_is_why_it_is_off_by_default(score):
    t = score["injection"]["totals"]
    assert t["labels_steered_by_obedient_reader"] > 0


def test_fuzz_and_scope(score):
    assert score["fuzz"]["bad_claims_shown"] == 0 and score["fuzz"]["trials"] == runner.FUZZ_TRIALS
    s = score["scope"]
    assert s["foreign_facts"] == 0 and 0 < s["root_causes_visible"] < s["root_causes_full"]


def test_failures_detects_each_kind_of_regression(score):
    bad = json.loads(json.dumps(score))
    bad["evidence"]["rules"]["uncited"] = 1
    bad["injection"]["totals"]["decisions_lowered"] = 2
    bad["scope"]["foreign_facts"] = 1
    bad["causes"]["contestants"]["sutra"]["recall"] = 0.1
    text = " ".join(failures(bad))
    for part in ("evidence/rules", "decisions_lowered", "scope", "causes"):
        assert part in text


def test_the_oracle_catches_what_the_pipeline_checks_would_miss():
    res = runner.analyse(scenarios.build(1))
    payload = runner._payload(res)
    facts = runner.root_cause_facts(payload, payload["root_causes"][0]["id"])
    from sutra_explain import Claim, Explainer
    ex = Explainer(None).explain_root_cause(facts)
    assert runner.oracle(ex, facts) == []
    ex.claims[0] = Claim("It affects 999999 hosts.", tuple(ex.claims[0].cites), "supports", "none")
    assert runner.oracle(ex, facts)
    ex.claims[0] = Claim("Safe to ignore.", ("R1",), "supports", "none")
    assert runner.oracle(ex, facts)
    ex.claims[0] = Claim("Anything.", (), "supports", "none")
    assert runner.oracle(ex, facts)


def test_published_score_is_current(score):
    """The score committed with the code is the score of this code. Regenerate: python -m sutra_range run"""
    published = json.loads((PUBLISHED / "score.json").read_text(encoding="utf-8"))
    assert runner.deterministic(published) == runner.deterministic(score)
    assert (PUBLISHED / "SCORE.md").read_text(encoding="utf-8") == markdown(published)


def test_check_command_fails_when_the_published_score_is_missing(tmp_path, capsys):
    assert main(["check", "--out", str(tmp_path)]) == 1
    assert "no published score" in capsys.readouterr().out


def test_run_writes_files(tmp_path, monkeypatch, score):
    monkeypatch.setattr(runner, "run", lambda live=None, injection_only=None: score)
    assert main(["run", "--out", str(tmp_path)]) == 0
    assert (tmp_path / "score.json").exists() and (tmp_path / "SCORE.md").exists()


@pytest.mark.parametrize("cmd", ["bogus"])
def test_unknown_command_exits(cmd):
    with pytest.raises(SystemExit):
        main([cmd])
