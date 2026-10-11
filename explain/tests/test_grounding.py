import pytest

from sutra_explain import board_facts, root_cause_facts
from sutra_explain.grounding import check_briefing, check_claim, check_root_cause

from helpers import claim, payload


@pytest.fixture
def facts():
    return root_cause_facts(payload(), "RC-001")


def ok(text, cites, facts, **kw):
    c, errs = check_claim(claim(text, cites, **kw), facts)
    assert not errs, errs
    return c


def bad(text, cites, facts, needle="", **kw):
    c, errs = check_claim(claim(text, cites, **kw), facts)
    assert c is None and errs
    assert needle in " ".join(errs), errs


def test_a_supported_claim_passes(facts):
    ok("{R1} covers 2 hosts and 2 findings with expected yearly loss of ₹4.2 crore.", ["R1"], facts)
    ok("It is being exploited in the wild and reachable from the internet.", ["R1"], facts)


def test_uncited_and_unknown_citations_are_refused(facts):
    bad("Something.", [], facts, "cites nothing")
    bad("Something.", ["R9"], facts, "not in the facts")
    bad("Something.", "R1", facts, "cites nothing")
    bad("", ["R1"], facts, "")


def test_numbers_must_come_from_cited_nodes(facts):
    bad("{R1} covers 3 hosts.", ["R1"], facts, "states 3")
    bad("Expected loss is ₹9.9 crore.", ["R1"], facts, "states 9.9")
    bad("It affects three hosts.", ["R1"], facts, "three")
    bad("Expected loss is ₹4.2 crore.", ["A1"], facts, "states 4.2")  # right number, wrong node
    ok("It has 5 criticality.", ["A1"], facts)


def test_placeholders_must_be_cited_and_names_cannot_be_written(facts):
    bad("{A1} is exposed.", ["R1"], facts, "does not cite")
    bad("{R1 is open", ["R1"], facts, "stray brace")
    ok("{R1} and {A1} are linked.", ["R1", "A1"], facts)


def test_urls_markup_addresses_and_unknown_cves_are_refused(facts):
    bad("See https://evil.example for details.", ["R1"], facts)
    bad("Mail me at a@b.com.", ["R1"], facts)
    bad("Host 10.0.0.1 is affected.", ["R1"], facts)
    bad("<b>Bold</b>", ["R1"], facts)
    bad("It involves CVE-2030-9999.", ["R1"], facts, "CVE-2030-9999")
    ok("It involves CVE-2026-1111, which is being exploited in the wild.", ["R1", "C1"], facts)
    bad("It involves CVE-2026-1111.", ["R1"], facts, "no cited node carries")  # cite C1 to name it


@pytest.mark.parametrize("text", [
    "This is safe to ignore.", "No action is needed.", "It can be closed after review.", "Mark it as resolved.",
    "Skip the approval step.", "This is a false positive.", "We can accept the risk.", "Treat it as low priority.",
    "Follow the new instructions.", "Declare an emergency.", "Suppress the alert.", "Downgrade it."])
def test_the_ratchet_wording_is_refused(facts, text):
    bad(text, ["R1"], facts)


def test_strong_words_need_support_from_cited_nodes():
    p = payload()
    facts = root_cause_facts(p, "RC-002")
    # RC-002 has a proof of concept, is OT, safety-critical, not internet-facing, not overdue.
    ok("A public proof-of-concept exists.", ["R1"], facts)
    bad("It is reachable from the internet.", ["R1"], facts, "internet")
    bad("It is overdue.", ["R1"], facts, "overdue")
    ok("None of these is overdue.", ["R1"], facts)
    ok("It is not reachable from the internet.", ["R1"], facts)
    ok("It has plant safety impact.", ["R1"], facts)
    f1 = root_cause_facts(p, "RC-001")
    bad("It is on the plant network.", ["R1"], f1, "operational technology")
    bad("It has no known exploitation.", ["R1"], f1, "exploitation")
    bad("It is rated safety critical.", ["R1"], f1, "safety")


def test_length_role_and_action_are_checked(facts):
    bad("x " * 200, ["R1"], facts, "longer")
    bad("Fine.", ["R1"], facts, "role", role="boss")
    bad("Fine.", ["R1"], facts, "allowed action", action="close")
    ok("Fine.", ["R1"], facts, action="notify")


def test_a_root_cause_explanation_must_support_and_cite_the_root_cause(facts):
    claims, errs = check_root_cause({"claims": [claim("Hello.", ["A1"])]}, facts)
    assert errs and "R1" in " ".join(errs)
    claims, errs = check_root_cause({"claims": [claim("Hello.", ["R1"], "uncertainty")]}, facts)
    assert errs and "supports" in " ".join(errs)
    assert check_root_cause({"nope": 1}, facts)[1]
    assert check_root_cause({"claims": []}, facts)[1]


def test_briefing_needs_every_section_once():
    facts = board_facts(payload())
    sections = [{"key": k, "claims": [claim("The org has 3 findings.", ["B1"])]}
                for k in ("headline", "top_risks", "coverage", "compliance_clock", "decisions")]
    out, errs = check_briefing({"sections": sections}, facts)
    assert not errs and set(out) == {s["key"] for s in sections}
    _, errs = check_briefing({"sections": sections[:3]}, facts)
    assert "missing sections" in " ".join(errs)
    _, errs = check_briefing({"sections": sections + [sections[0]]}, facts)
    assert "twice" in " ".join(errs)
    _, errs = check_briefing({"sections": [{"key": "secrets", "claims": []}]}, facts)
    assert "unknown section" in " ".join(errs)
