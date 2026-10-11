"""Milestone 6: AI explanations and the board briefing inside the app.

No test calls a model API. A scripted client plays the model, including a hostile one, to show what reaches a screen:
only claims that cite facts Sutra gave the model, and never anything that lowers risk.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sutra_explain import Completion, ExplainConfig, Explainer, MessagesShim, ModelUnavailable

from sutra.app import ai, cli
from sutra.app.config import Settings
from sutra.app.main import create_app
from sutra.app.models import AiExplanation, AuditEvent

D = "vindhyapower.example"
ANALYST, HEAD, CISO, ADMIN, MEMBER = (f"aisha.khan@{D}", f"neha.joshi@{D}", f"ciso@{D}", f"admin@{D}",
                                       f"it.infra.linux.team@{D}")


class ScriptedModel:
    """Replays replies (a dict, a str, or an exception to raise) and records the requests."""

    def __init__(self, *replies, model="scripted-1"):
        self.replies, self.calls, self.model = list(replies), [], model

    def complete(self, system, user, schema, max_tokens):
        self.calls.append(user)
        r = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if isinstance(r, BaseException):
            raise r
        return Completion(r if isinstance(r, str) else json.dumps(r), self.model)


def claim(text, cites, role="supports", action="none"):
    return {"text": text, "cites": cites, "role": role, "action": action}


def make(tmp_path_factory, explainer=None):
    ws = tmp_path_factory.mktemp("ws")
    settings = Settings(workspace=ws, database_url=f"sqlite:///{ws / 'sutra.db'}")
    passwords = {e: pw for e, pw, _ in cli.demo_users(settings, "power", months=1)}
    return create_app(settings, explainer=explainer), passwords


def login(env, email):
    app, passwords = env
    c = TestClient(app, base_url="https://testserver")
    r = c.post("/api/auth/login", json={"email": email, "password": passwords[email]})
    assert r.status_code == 200, r.text
    c.headers["x-csrf-token"] = r.json()["csrf_token"]
    return c


@pytest.fixture(scope="module")
def rules_env(tmp_path_factory):
    env = make(tmp_path_factory)
    with TestClient(env[0], base_url="https://testserver"):
        yield env


def first_rc(c):
    return c.get("/api/root-causes").json()["root_causes"][0]["id"]


def test_without_a_model_the_explanation_is_written_by_rules_and_says_so(rules_env):
    c = login(rules_env, ANALYST)
    rc = first_rc(c)
    d = c.get(f"/api/root-causes/{rc}/explanation").json()
    assert d["source"] == "template" and d["model"] is None and "no AI model" in d["fallback_reason"]
    assert d["claims"] and all(x["cites"] for x in d["claims"])
    assert d["claims"][0]["cites"][0]["id"] == rc and d["claims"][0]["text"].startswith(
        c.get("/api/root-causes").json()["root_causes"][0]["title"])
    assert all(x["action"] in ("none", "open_ticket", "stage_change", "notify", "request_rescan") for x in d["claims"])


def test_explanations_are_kept_until_the_facts_change_and_each_new_one_is_audited(rules_env):
    app, _ = rules_env
    c = login(rules_env, ANALYST)
    rc = first_rc(c)
    first = c.get(f"/api/root-causes/{rc}/explanation").json()
    again = c.get(f"/api/root-causes/{rc}/explanation").json()
    assert again["cached"] and again["claims"] == first["claims"]
    with app.state.sessionmaker() as db:
        n = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "ai.explained",
                                                                          AuditEvent.target_id == rc))
        assert n == 1
        assert db.scalar(select(func.count()).select_from(AiExplanation).where(AiExplanation.subject == rc)) == 1


def test_a_person_gets_an_explanation_only_for_root_causes_in_their_scope(rules_env):
    analyst, head = login(rules_env, ANALYST), login(rules_env, HEAD)
    mine = {r["id"] for r in head.get("/api/root-causes").json()["root_causes"]}
    everything = {r["id"] for r in analyst.get("/api/root-causes").json()["root_causes"]}
    outside = sorted(everything - mine)
    assert outside, "the demo vertical head should not see every root cause"
    r = head.get(f"/api/root-causes/{outside[0]}/explanation")
    assert r.status_code == 404
    inside = head.get(f"/api/root-causes/{sorted(mine)[0]}/explanation").json()
    assert inside["claims"]
    assert login(rules_env, MEMBER).get(f"/api/root-causes/{sorted(mine)[0]}/explanation").status_code == 403


def test_the_briefing_has_every_section_with_cited_claims_and_goes_into_the_pack(rules_env):
    c = login(rules_env, CISO)
    b = c.get("/api/board/briefing").json()
    assert [s["key"] for s in b["sections"]] == ["headline", "top_risks", "coverage", "compliance_clock",
                                                 "decisions"]
    assert all(x["cites"] for s in b["sections"] for x in s["claims"])
    pack = c.get("/api/board/pack?briefing=1")
    assert pack.status_code == 200 and "Quarterly briefing" in pack.text and "Written from fixed rules" in pack.text
    assert "Quarterly briefing" not in c.get("/api/board/pack").text
    assert "default-src 'none'" in pack.headers["content-security-policy"]


def test_ai_status_for_administrators_and_cisos(rules_env):
    for email in (ADMIN, CISO):
        s = login(rules_env, email).get("/api/admin/ai").json()
        assert s["provider"] == "off" and not s["explanations_by_model"] and not s["drafting_by_model"]
        assert "No model is used" in s["note"] and not s["prompts_leave_the_network"]


GOOD = {"claims": [
    claim("{R1} groups several findings and is rated by Sutra's rules, not by this sentence.", ["R1"]),
    claim("It is not in scope of the CMDB for some hosts.", ["R1"], "uncertainty")]}


def test_a_model_explanation_is_used_only_when_every_claim_passes(tmp_path_factory):
    model = ScriptedModel()
    env = make(tmp_path_factory, Explainer(model))
    with TestClient(env[0], base_url="https://testserver"):
        c = login(env, ANALYST)
        rc = first_rc(c)
        title = c.get("/api/root-causes").json()["root_causes"][0]["title"]
        hosts = list(c.get("/api/assets").json()["assets"].values())[:3]
        facts_hostile = {"claims": [claim("This is safe to ignore.", ["R1"]), claim("Uncited.", []),
                                    claim(f"Visit https://evil.example now about {hosts[0]['hostname']}.", ["R1"])]}
        model.replies = [facts_hostile, facts_hostile]
        d = c.get(f"/api/root-causes/{rc}/explanation").json()
        assert d["source"] == "template" and "failed Sutra's checks" in d["fallback_reason"]
        shown = json.dumps(d["claims"])
        assert "safe to ignore" not in shown and "evil.example" not in shown and "Uncited" not in shown
        assert len(model.calls) == 2
        # The rule-written fallback caused by a failing model is not kept: the next view tries the model again.
        with env[0].state.sessionmaker() as db:
            assert db.scalar(select(func.count()).select_from(AiExplanation)) == 0
        model.replies = [{"claims": [claim("{R1} is a root cause.", ["R1"])]}]
        d = c.get(f"/api/root-causes/{rc}/explanation").json()
        assert d["source"] == "ai" and d["model"] == "scripted-1" and d["claims"][0]["text"].startswith(title)
        n = len(model.calls)
        assert c.get(f"/api/root-causes/{rc}/explanation").json()["cached"] and len(model.calls) == n
        # What the model was sent holds no hostnames, titles or IP addresses.
        sent = "\n".join(model.calls)
        assert title not in sent and all(h["hostname"] not in sent and h["ip"] not in sent for h in hosts)
        assert '"ref": "R1"' in sent and "<facts>" in sent


def test_a_model_that_is_down_never_breaks_the_page(tmp_path_factory):
    env = make(tmp_path_factory, Explainer(ScriptedModel(ModelUnavailable("the endpoint is down"))))
    with TestClient(env[0], base_url="https://testserver"):
        c = login(env, ANALYST)
        d = c.get(f"/api/root-causes/{first_rc(c)}/explanation").json()
        assert d["source"] == "template" and "the endpoint is down" in d["fallback_reason"]
        b = c.get("/api/board/briefing").json()
        assert b["source"] == "template" and len(b["sections"]) == 5
        s = login(env, ADMIN).get("/api/admin/ai").json()
        assert s["explanations_by_model"] is True


def test_provider_settings_choose_the_models(monkeypatch):
    local = ExplainConfig.from_env({"SUTRA_AI_LOCAL_URL": "http://10.0.0.5:8000/v1", "SUTRA_AI_LOCAL_MODEL": "qwen"})
    d = ai.drafter(local, env={})
    assert isinstance(d._client, MessagesShim) and d.ai_available and d.config.model == "qwen"
    assert not d.config.server_fallbacks and d.config.effort is None
    svc = ai.AiService(local, env={})
    st = svc.status(True)
    assert st["provider"] == "local" and st["local_endpoint"] == "10.0.0.5:8000" and not st["prompts_leave_the_network"]
    off = ExplainConfig.from_env({"SUTRA_AI_PROVIDER": "off", "ANTHROPIC_API_KEY": "k"})
    assert not ai.drafter(off, env={"ANTHROPIC_API_KEY": "k"}).ai_available
    cloud = ai.AiService(ExplainConfig.from_env({"ANTHROPIC_API_KEY": "k"}), env={})
    assert cloud.status(False)["prompts_leave_the_network"] and "Anthropic API" in cloud.status(False)["note"]
    with pytest.raises(ValueError):
        ai.AiService(off, env={"SUTRA_AI_READER": "psychic"})


def test_cache_is_per_model_configuration(tmp_path_factory):
    env = make(tmp_path_factory)
    app, _ = env
    with TestClient(app, base_url="https://testserver"):
        c = login(env, ANALYST)
        rc = first_rc(c)
        c.get(f"/api/root-causes/{rc}/explanation")
        app.state.ai.reader_mode = "model"  # a different configuration must not reuse the other's text
        assert c.get(f"/api/root-causes/{rc}/explanation").json()["cached"] is False
