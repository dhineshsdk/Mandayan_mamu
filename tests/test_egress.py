"""Milestone 7: an outbound allow-list, so an installation keeps its data inside the customer's network."""

from __future__ import annotations

import socket
import threading

import pytest
from fastapi.testclient import TestClient
from sutra_explain import ExplainConfig

from sutra.app import ai, cli, egress
from sutra.app.config import Settings
from sutra.app.main import create_app

D = "vindhyapower.example"


@pytest.fixture(autouse=True)
def _restore_sockets():
    yield
    egress.uninstall()


def guard(*allow, policy="allowlist"):
    return egress.EgressGuard(policy, list(allow))


# ---------------------------------------------------------------- decisions
def test_default_is_deny_for_public_names_and_addresses():
    g = guard()
    for host in ("api.anthropic.com", "hooks.slack.com", "8.8.8.8", "2606:4700:4700::1111", "example.in"):
        assert not g.host_allowed(host), host


def test_the_private_network_is_always_reachable():
    g = guard()
    for host in ("localhost", "127.0.0.1", "::1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "169.254.1.1", "postgres",
                 "jira", "0.0.0.0", "", None):  # noqa: S104 - address strings under test, nothing binds
        assert g.host_allowed(host), host


def test_allow_entries_names_suffixes_and_networks():
    g = guard("jira.example.in", "*.corp.example.in", ".teams.example.in", "52.66.0.0/24", "13.232.0.7")
    assert g.host_allowed("jira.example.in") and g.host_allowed("JIRA.example.in.")
    assert not g.host_allowed("evil-jira.example.in") and not g.host_allowed("example.in")
    assert g.host_allowed("a.corp.example.in") and g.host_allowed("a.b.corp.example.in")
    assert not g.host_allowed("corp.example.in") and not g.host_allowed("notcorp.example.in")
    assert g.host_allowed("x.teams.example.in")
    assert g.host_allowed("52.66.0.55") and not g.host_allowed("52.67.0.1")
    assert g.host_allowed("13.232.0.7") and not g.host_allowed("13.232.0.8")


def test_open_policy_restricts_nothing_and_bad_policy_is_refused():
    assert guard(policy="open").host_allowed("anything.example.com")
    with pytest.raises(ValueError, match="SUTRA_EGRESS"):
        egress.EgressGuard("maybe")
    assert egress.parse_allow("a.in, .b.in\n10.0.0.0/8,,") == ["a.in", ".b.in", "10.0.0.0/8"]


# ---------------------------------------------------------------- real sockets
def test_name_lookups_and_connections_are_refused_before_any_network_use():
    g = guard()
    egress.install(g)
    with pytest.raises(egress.EgressBlocked, match="api.anthropic.com is not on the allow-list"):
        socket.create_connection(("api.anthropic.com", 443), timeout=1)
    with pytest.raises(egress.EgressBlocked):
        socket.getaddrinfo("example.in", 80)
    s = socket.socket()
    try:
        with pytest.raises(egress.EgressBlocked):
            s.connect(("8.8.8.8", 53))
        with pytest.raises(egress.EgressBlocked):
            s.connect_ex(("8.8.4.4", 53))
    finally:
        s.close()
    hosts = {b["host"]: b["count"] for b in g.status()["blocked"]}
    assert hosts["api.anthropic.com"] == 1 and hosts["8.8.8.8"] == 1 and hosts["example.in"] == 1


def test_local_connections_still_work():
    egress.install(guard())
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    got = []
    t = threading.Thread(target=lambda: got.append(server.accept()[0].recv(5)))
    t.start()
    c = socket.create_connection(("localhost", port), timeout=2)
    c.sendall(b"hello")
    c.close()
    t.join(3)
    server.close()
    assert got == [b"hello"]


def test_an_allowed_name_may_connect_to_the_addresses_it_resolves_to(monkeypatch):
    g = guard("api.example.in")
    monkeypatch.setattr(egress, "_real_getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("52.66.1.9", 443))])
    egress.install(g)
    assert socket.getaddrinfo("api.example.in", 443)[0][4][0] == "52.66.1.9"
    assert g.ip_allowed("52.66.1.9") and not g.ip_allowed("52.66.1.10")
    assert g.status()["blocked"] == []


def test_uninstall_restores_and_only_the_owner_may_lift_it():
    a, b = guard(), guard()
    egress.install(a)
    egress.install(b)
    egress.uninstall(a)  # a is not the active guard: ignored
    with pytest.raises(egress.EgressBlocked):
        socket.getaddrinfo("example.in", 80)
    egress.uninstall(b)
    assert socket.getaddrinfo is egress._real_getaddrinfo
    egress.install(guard(policy="open"))
    assert egress._current is None


# ---------------------------------------------------------------- the application
def make(tmp_path, **kw):
    ws = tmp_path / "ws"
    settings = Settings(workspace=ws, database_url=f"sqlite:///{ws / 'sutra.db'}", **kw)
    passwords = {e: pw for e, pw, _ in cli.demo_users(settings, "power", months=1)}
    return create_app(settings), passwords


def test_a_cloud_model_is_switched_off_by_the_policy_and_the_screen_says_why(tmp_path, monkeypatch):
    monkeypatch.setenv("SUTRA_AI_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")  # noqa: S105
    app, pw = make(tmp_path, egress_policy="allowlist", egress_allow="")
    with TestClient(app, base_url="https://testserver") as c:
        r = c.post("/api/auth/login", json={"email": f"admin@{D}", "password": pw[f"admin@{D}"]})
        assert r.status_code == 200
        st = c.get("/api/admin/ai").json()
        assert st["provider"] == "off"
        assert "api.anthropic.com is not on this server's outbound allow-list" in st["reason"]
        assert st["egress"]["policy"] == "allowlist" and st["egress"]["allow"] == []
        assert st["explanations_by_model"] is False and st["drafting_by_model"] is False
        assert socket.getaddrinfo is not egress._real_getaddrinfo, "the guard is live while the app runs"
        with pytest.raises(egress.EgressBlocked):
            socket.getaddrinfo("example.in", 80)
        assert [b["host"] for b in c.get("/api/admin/ai").json()["egress"]["blocked"]] == ["example.in"]
    assert socket.getaddrinfo is egress._real_getaddrinfo, "shutting the app down lifts it"


def test_allowing_the_host_lets_the_model_through(tmp_path, monkeypatch):
    monkeypatch.setenv("SUTRA_AI_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")  # noqa: S105
    app, pw = make(tmp_path, egress_policy="allowlist", egress_allow="api.anthropic.com")
    with TestClient(app, base_url="https://testserver") as c:
        c.post("/api/auth/login", json={"email": f"admin@{D}", "password": pw[f"admin@{D}"]})
        assert c.get("/api/admin/ai").json()["provider"] == "anthropic"


def test_a_local_model_inside_the_network_needs_no_listing_but_a_public_one_does():
    cfg = ExplainConfig(provider="local", local_url="http://10.4.0.20:8000/v1", local_model="m")
    g = guard()
    assert ai.blocked_by_policy(cfg, g).provider == "local"
    far = ExplainConfig(provider="local", local_url="https://llm.vendor.example.com/v1", local_model="m")
    off = ai.blocked_by_policy(far, g)
    assert off.provider == "off" and "llm.vendor.example.com" in off.reason
    assert ai.blocked_by_policy(far, guard("llm.vendor.example.com")).provider == "local"
    assert ai.blocked_by_policy(far, None) is far and ai.blocked_by_policy(far, guard(policy="open")) is far


def test_default_install_is_not_restricted(tmp_path):
    app, _ = make(tmp_path)
    assert app.state.egress.policy == "open"
    with TestClient(app, base_url="https://testserver"):
        assert socket.getaddrinfo is egress._real_getaddrinfo or egress._current is None
