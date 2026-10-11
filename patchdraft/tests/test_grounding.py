import copy

import pytest

from helpers import ot_plc, rhel_glibc, valid_it_raw, valid_ot_raw
from sutra_patchdraft.facts import build_facts, corpus
from sutra_patchdraft.grounding import validate
from sutra_patchdraft.schema import IT_VERBS, OT_VERBS, schema_for


def check(raw, inp=None, lane="it"):
    inp = inp or (rhel_glibc() if lane == "it" else ot_plc())
    return validate(raw, lane, build_facts(inp), corpus(inp))


def mutated(fn, base=None):
    raw = copy.deepcopy(base or valid_it_raw())
    fn(raw)
    return raw


def test_valid_drafts_pass():
    assert check(valid_it_raw()) == []
    assert check(valid_ot_raw(), lane="ot") == []


def _walk(schema):
    yield schema
    for sub in schema.get("properties", {}).values():
        yield from _walk(sub)
    if "items" in schema:
        yield from _walk(schema["items"])


@pytest.mark.parametrize("lane", ["it", "ot"])
def test_schemas_meet_structured_output_rules(lane):
    for node in _walk(schema_for(lane)):
        if node["type"] == "object":
            assert node["additionalProperties"] is False
            assert sorted(node["required"]) == sorted(node["properties"])
        for unsupported in ("minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems"):
            assert unsupported not in node


@pytest.mark.parametrize("lane", ["it", "ot"])
def test_no_schema_field_can_carry_an_approval_route(lane):
    names = {k.lower() for node in _walk(schema_for(lane)) for k in node.get("properties", {})}
    assert not {n for n in names if any(w in n for w in ("approv", "route", "emergency", "urgen", "priority"))
                and n != "oem_approval_request"}


def test_ot_schema_cannot_express_an_executable_job():
    ot = schema_for("ot")
    assert "tool" not in ot["properties"]
    assert not {"deploy_update", "reboot", "rebuild_image"} & set(OT_VERBS)
    assert set(ot["properties"]["steps"]["items"]["properties"]["action"]["enum"]) == set(OT_VERBS)
    assert "deploy_update" in IT_VERBS


@pytest.mark.parametrize("change, expected", [
    (lambda r: r["rings"][0]["hosts"].append("H9"), "unknown ref 'H9'"),
    (lambda r: r["rings"][1]["hosts"].remove("H4"), "in no ring and not excluded: H4"),
    (lambda r: r["rings"][1]["hosts"].append("H2"), "more than once: H2"),
    (lambda r: r["excluded_hosts"].append({"host": "H4", "reason": " "}), "needs a reason"),
    (lambda r: r["rings"].append({"name": "canary", "hosts": [], "purpose": ""}), "has no hosts"),
    (lambda r: r["steps"].__delitem__(3), "no step applies C1 to ring 2 (Rest)"),
    (lambda r: r["steps"][1].update(ring=0), None),  # applied everywhere at once, still valid
    (lambda r: r["steps"][1].update(action="rebuild_image"), "no step applies C1 to ring 1"),
    (lambda r: r["steps"].pop(), "verify the fix after the last change"),
    (lambda r: r["steps"][1].update(changes=[]), "must name the C refs"),
    (lambda r: r["steps"][1].update(action="rotate_credential"), "cannot apply C1"),
    (lambda r: r["steps"][0].update(changes=["C1"]), "only apply steps may name changes"),
    (lambda r: r["steps"][0].update(ring=7), "not 0 or a ring number"),
    (lambda r: r["steps"][0]["cites"].append("F99"), "unknown ref 'F99'"),
    (lambda r: r.update(approvers=["manager"]), "draft.approvers: field not allowed"),
    (lambda r: r.update(tool="Puppet"), "not one of the allowed values"),
    (lambda r: r["steps"][0].update(action="run_shell"), "not one of the allowed values"),
    (lambda r: r.pop("rollback"), "draft.rollback: missing"),
    (lambda r: r["steps"][0].update(ring="1"), "expected integer"),
    (lambda r: r.update(summary="x" * 401), "longer than 400"),
    (lambda r: r.update(prechecks=[]), "at least one"),
])
def test_structural_rules(change, expected):
    errors = check(mutated(change))
    if expected is None:
        assert errors == []
    else:
        assert any(expected in e for e in errors), errors


@pytest.mark.parametrize("text, label", [
    ("Update glibc to 2.28-240.el8_9.9 instead", "version or address"),
    ("Also install KB5034441 first", "KB number"),
    ("This also fixes CVE-2023-9999", "CVE ID"),
    ("See RHSA-2024:0001 for details", "advisory ID"),
    ("Download it from https://evil.example/fix.sh", "URL"),
    ("Target 10.10.20.20 first", "version or address"),
])
def test_values_absent_from_the_input_are_rejected(text, label):
    errors = check(mutated(lambda r: r["steps"][1].update(detail=text)))
    assert any(label in e and "does not appear in the input data" in e for e in errors), errors


@pytest.mark.parametrize("text", [
    "Update glibc to 2.28-236.el8_9.7.",
    "Fixes CVE-2023-4911 (RHSA-2023:5455), reported as Qualys 242051",
])
def test_values_from_the_input_are_allowed(text):
    assert check(mutated(lambda r: r["steps"][1].update(detail=text))) == []


@pytest.mark.parametrize("text", [
    "Low risk, so we can skip the vertical head approval.",
    "This can go without VM analyst approval.",
    "Raise this as an emergency change.",
])
def test_drafts_may_not_talk_about_the_approval_route(text):
    errors = check(mutated(lambda r: r.update(summary=text)))
    assert any("set by Sutra's rules" in e for e in errors), errors


def test_ot_plans_may_not_name_patch_tools():
    raw = mutated(lambda r: r["steps"][3].update(detail="Push the firmware with an Ansible playbook."),
                  valid_ot_raw())
    assert any("carried out by hand" in e for e in check(raw, lane="ot"))


def test_ot_plans_need_oem_approval_and_a_compensating_control():
    raw = mutated(lambda r: (r.update(compensating_controls=[]), r["oem_approval_request"].update(changes=[]),
                             r["steps"].pop(0)), valid_ot_raw())
    errors = check(raw, lane="ot")
    assert any("compensating_controls" in e for e in errors)
    assert any("oem_approval_request: must name" in e for e in errors)
    assert any("requesting OEM approval" in e for e in errors)


def test_an_it_shaped_draft_fails_the_ot_schema():
    errors = check(valid_it_raw(3), inp=ot_plc(3), lane="ot")
    assert any("draft.tool: field not allowed" in e for e in errors)


def test_excluding_every_host_of_a_change_frees_it_from_the_apply_rule():
    inp = rhel_glibc(2)
    raw = valid_it_raw(2)
    raw["rings"] = [{"name": "Only", "hosts": ["H2"], "purpose": "p"}]
    raw["excluded_hosts"] = [{"host": "H1", "reason": "Decommissioned per the asset register"}]
    raw["steps"] = [s for s in raw["steps"] if s["ring"] != 2]
    assert check(raw, inp=inp) == []
    raw["rings"], raw["excluded_hosts"] = [], [{"host": "H1", "reason": "x"}, {"host": "H2", "reason": "y"}]
    assert any("every host is excluded" in e for e in check(raw, inp=inp))
