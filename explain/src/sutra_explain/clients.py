"""Model clients. A client has one method, ``complete``, and the two kinds here behave the same to the rest of Sutra.

``AnthropicClient`` calls Claude with structured outputs. ``LocalClient`` calls any OpenAI-compatible chat endpoint
that runs inside the customer's own network (vLLM, llama.cpp server, Ollama, LM Studio), so an air-gapped site can use
a local model and no data leaves the box. Both return the model's text; Sutra's own checks decide whether to use it.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


class ModelUnavailable(Exception):
    """The endpoint could not be reached or returned an error."""


class ModelDeclined(Exception):
    """The model refused the request."""


class ModelTruncated(Exception):
    """The reply hit the token limit."""


@dataclass(frozen=True)
class Completion:
    text: str
    model: str


class AnthropicClient:
    def __init__(self, model: str, api_key: str | None = None, timeout: float = 120.0, effort: str | None = None,
                 sdk: Any = None):
        if sdk is None:
            try:
                import anthropic
            except ImportError as e:
                raise ModelUnavailable("the anthropic package is not installed: pip install 'sutra-explain[ai]'") from e
            sdk = anthropic.Anthropic(api_key=api_key, timeout=timeout, max_retries=2) if api_key else \
                anthropic.Anthropic(timeout=timeout, max_retries=2)
        self._sdk, self.model, self.effort = sdk, model, effort

    def complete(self, system: str, user: str, schema: dict, max_tokens: int) -> Completion:
        output_config: dict = {"format": {"type": "json_schema", "schema": schema}}
        if self.effort:
            output_config["effort"] = self.effort
        try:
            r = self._sdk.messages.create(model=self.model, max_tokens=max_tokens, system=system,
                                          messages=[{"role": "user", "content": user}], output_config=output_config)
        except Exception as e:  # noqa: BLE001 - SDK error types vary; callers only need to know it failed
            raise ModelUnavailable(f"the Claude API call failed ({type(e).__name__})") from e
        if r.stop_reason == "refusal":
            raise ModelDeclined("the model declined")
        if r.stop_reason == "max_tokens":
            raise ModelTruncated("the reply was cut off")
        text = "".join(b.text for b in r.content if getattr(b, "type", None) == "text")
        if not text:
            raise ModelUnavailable("the reply was empty")
        return Completion(text, getattr(r, "model", None) or self.model)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class LocalClient:
    """Chat completions against an endpoint on the customer's network. Redirects are refused so a misconfigured or
    hijacked endpoint cannot send prompts somewhere else."""

    def __init__(self, base_url: str, model: str, api_key: str = "", timeout: float = 300.0):
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("SUTRA_AI_LOCAL_URL must be an http(s) URL such as http://localhost:11434/v1")
        self.base_url, self.model, self.api_key, self.timeout = base_url.rstrip("/"), model, api_key, timeout
        self._opener = urllib.request.build_opener(_NoRedirect)

    def complete(self, system: str, user: str, schema: dict, max_tokens: int) -> Completion:
        body = {"model": self.model, "max_tokens": max_tokens, "temperature": 0,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "response_format": {"type": "json_schema",
                                    "json_schema": {"name": "sutra_reply", "schema": schema, "strict": True}}}
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(  # noqa: S310 - scheme is checked in __init__
            f"{self.base_url}/chat/completions", data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:  # noqa: S310
                data = json.loads(resp.read(8_000_000))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            raise ModelUnavailable(f"the local model endpoint failed ({type(e).__name__})") from e
        try:
            choice = data["choices"][0]
            text = choice["message"]["content"] or ""
            finish = choice.get("finish_reason")
        except (KeyError, IndexError, TypeError) as e:
            raise ModelUnavailable("the local model endpoint returned an unexpected reply") from e
        if finish == "length":
            raise ModelTruncated("the reply was cut off")
        if not text.strip():
            raise ModelUnavailable("the reply was empty")
        return Completion(text, str(data.get("model") or self.model))


class _Block:
    def __init__(self, text: str):
        self.type, self.text = "text", text


class _Response:
    def __init__(self, text: str, model: str, stop: str):
        self.content, self.model, self.stop_reason, self.stop_details = [_Block(text)], model, stop, None


class _Messages:
    def __init__(self, client: LocalClient):
        self._c = client

    def create(self, **kw):
        """The slice of ``anthropic.Anthropic().messages.create`` that sutra_patchdraft uses."""
        fmt = (kw.get("output_config") or {}).get("format") or {}
        user = "\n\n".join(m["content"] for m in kw["messages"] if isinstance(m.get("content"), str))
        try:
            c = self._c.complete(kw.get("system", ""), user, fmt.get("schema", {"type": "object"}),
                                 int(kw.get("max_tokens", 4000)))
        except ModelTruncated:
            return _Response("", self._c.model, "max_tokens")
        except ModelDeclined:
            return _Response("", self._c.model, "refusal")
        return _Response(c.text, c.model, "end_turn")


class MessagesShim:
    """Lets ``PatchDrafter(client=MessagesShim(local))`` draft with a local model. Connection errors raise
    ``ModelUnavailable``, which ``api_errors`` tells patchdraft to handle by falling back to its template."""

    api_errors = (ModelUnavailable,)  # patchdraft treats these like Anthropic API errors and uses its template

    def __init__(self, client: LocalClient):
        self.messages = _Messages(client)
