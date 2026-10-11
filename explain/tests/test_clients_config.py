import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from sutra_explain import (
    AnthropicClient,
    ExplainConfig,
    Explainer,
    LocalClient,
    MessagesShim,
    ModelDeclined,
    ModelTruncated,
    ModelUnavailable,
    root_cause_facts,
)

from helpers import GOOD_RC, payload


class Handler(BaseHTTPRequestHandler):
    reply: dict = {}
    seen: list = []
    status = 200

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Handler.seen.append((self.path, dict(self.headers), body))
        if Handler.status in (301, 302):
            self.send_response(Handler.status)
            self.send_header("Location", "http://127.0.0.1:1/elsewhere")
            self.end_headers()
            return
        data = json.dumps(Handler.reply).encode()
        self.send_response(Handler.status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    Handler.seen, Handler.status = [], 200
    Handler.reply = {"model": "local-1", "choices": [{"finish_reason": "stop",
                                                      "message": {"content": json.dumps(GOOD_RC)}}]}
    yield f"http://127.0.0.1:{srv.server_port}/v1"
    srv.shutdown()


def test_local_client_posts_a_schema_bound_request_to_the_configured_endpoint(server):
    c = LocalClient(server, "llama-x", api_key="k")
    out = c.complete("SYS", "USER", {"type": "object"}, 100)
    assert out.model == "local-1" and json.loads(out.text) == GOOD_RC
    path, headers, body = Handler.seen[0]
    assert path == "/v1/chat/completions" and headers["Authorization"] == "Bearer k"
    assert body["messages"][0] == {"role": "system", "content": "SYS"} and body["temperature"] == 0
    assert body["response_format"]["json_schema"]["strict"] is True


def test_local_client_errors(server):
    c = LocalClient(server, "m")
    Handler.reply = {"choices": [{"finish_reason": "length", "message": {"content": "{"}}]}
    with pytest.raises(ModelTruncated):
        c.complete("s", "u", {}, 10)
    Handler.reply = {"oops": 1}
    with pytest.raises(ModelUnavailable):
        c.complete("s", "u", {}, 10)
    Handler.status = 500
    with pytest.raises(ModelUnavailable):
        c.complete("s", "u", {}, 10)
    Handler.status = 302
    with pytest.raises(ModelUnavailable):  # redirects are refused, so prompts cannot be sent elsewhere
        c.complete("s", "u", {}, 10)
    with pytest.raises(ModelUnavailable):
        LocalClient("http://127.0.0.1:9/v1", "m", timeout=1).complete("s", "u", {}, 10)


def test_local_client_rejects_non_http_urls():
    for url in ("file:///etc/passwd", "ftp://x/y", "localhost:11434", ""):
        with pytest.raises(ValueError):
            LocalClient(url, "m")


def test_the_explainer_works_end_to_end_against_a_local_model(server):
    facts = root_cause_facts(payload(), "RC-001")
    ex = Explainer(LocalClient(server, "m")).explain_root_cause(facts)
    assert ex.source == "ai" and ex.model == "local-1"


def test_shim_lets_patchdraft_use_a_local_model(server):
    from datetime import date

    from sutra_patchdraft import DraftInput, HostInput, PatchDrafter, RootCauseInput
    from sutra_patchdraft.drafter import DrafterConfig
    cfg = DrafterConfig(adaptive_thinking=False, effort=None, server_fallbacks=False, max_attempts=1)
    inp = DraftInput(RootCauseInput("RC-1", "single", "k", "t", "f"), (HostInput("A1", "h1"),), (), date(2026, 10, 11))
    Handler.reply = {"model": "local-1", "choices": [{"finish_reason": "stop", "message": {"content": "{}"}}]}
    drafter = PatchDrafter(config=cfg, client=MessagesShim(LocalClient(server, "m")))
    d = drafter.draft(inp)  # {} does not pass patchdraft's checks, so the template writes the job and says why
    assert d.source == "template" and "failed Sutra's checks" in d.fallback_reason
    drafter = PatchDrafter(config=cfg, client=MessagesShim(LocalClient("http://127.0.0.1:9/v1", "m", timeout=1)))
    d = drafter.draft(inp)  # nothing is listening: the job is still drafted, from the template
    assert d.source == "template" and d.fallback_reason


class FakeSdk:
    def __init__(self, stop="end_turn", text="{}"):
        self.calls = []
        self.stop, self.text = stop, text
        self.messages = self

    def create(self, **kw):
        self.calls.append(kw)
        if self.stop == "boom":
            raise RuntimeError("x")

        class R:
            stop_reason, model = self.stop, "claude-test"
            content = [type("B", (), {"type": "text", "text": self.text})()]
        return R()


def test_anthropic_client_uses_structured_outputs_and_maps_stop_reasons():
    sdk = FakeSdk()
    c = AnthropicClient("claude-sonnet-5-5", sdk=sdk, effort="medium")
    assert c.complete("s", "u", {"type": "object"}, 50).model == "claude-test"
    kw = sdk.calls[0]
    assert kw["output_config"] == {"format": {"type": "json_schema", "schema": {"type": "object"}},
                                   "effort": "medium"}
    assert kw["system"] == "s" and kw["messages"] == [{"role": "user", "content": "u"}]
    with pytest.raises(ModelDeclined):
        AnthropicClient("m", sdk=FakeSdk("refusal")).complete("s", "u", {}, 5)
    with pytest.raises(ModelTruncated):
        AnthropicClient("m", sdk=FakeSdk("max_tokens")).complete("s", "u", {}, 5)
    with pytest.raises(ModelUnavailable):
        AnthropicClient("m", sdk=FakeSdk("boom")).complete("s", "u", {}, 5)


def test_config_resolution():
    assert ExplainConfig.from_env({}).provider == "off"
    assert "no AI model" in ExplainConfig.from_env({}).reason
    assert ExplainConfig.from_env({"ANTHROPIC_API_KEY": "k"}).provider == "anthropic"
    c = ExplainConfig.from_env({"ANTHROPIC_API_KEY": "k", "SUTRA_AI_LOCAL_URL": "http://h/v1",
                                "SUTRA_AI_LOCAL_MODEL": "m"})
    assert c.provider == "local" and c.air_gapped_safe  # a local model wins, so nothing leaves the network
    assert not ExplainConfig.from_env({"ANTHROPIC_API_KEY": "k"}).air_gapped_safe
    assert ExplainConfig.from_env({"SUTRA_AI_PROVIDER": "local"}).provider == "off"
    assert ExplainConfig.from_env({"SUTRA_AI_PROVIDER": "anthropic"}).provider == "off"
    assert ExplainConfig.from_env({"ANTHROPIC_API_KEY": "k", "SUTRA_AI_EXPLAIN": "off"}).provider == "off"
    assert ExplainConfig.from_env({"SUTRA_AI_EXPLAIN_EFFORT": "none"}).effort is None
    with pytest.raises(ValueError):
        ExplainConfig.from_env({"SUTRA_AI_PROVIDER": "skynet"})
    with pytest.raises(ValueError):
        ExplainConfig.from_env({"SUTRA_AI_ATTEMPTS": "many"})


def test_build_client_and_explainer_from_config():
    off = Explainer.from_config(ExplainConfig.from_env({}))
    assert not off.ai_available and "no AI model" in off.unavailable
    c = ExplainConfig.from_env({"SUTRA_AI_LOCAL_URL": "http://127.0.0.1:1/v1", "SUTRA_AI_LOCAL_MODEL": "m"})
    assert isinstance(c.build_client()[0], LocalClient)
    bad = ExplainConfig.from_env({"SUTRA_AI_LOCAL_URL": "nonsense", "SUTRA_AI_LOCAL_MODEL": "m"})
    assert bad.build_client()[0] is None and "http" in bad.build_client()[1]
