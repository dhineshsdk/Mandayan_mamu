"""Which model Sutra uses for explanations, read from ``SUTRA_AI_*`` variables.

* ``SUTRA_AI_PROVIDER``: ``auto`` (default), ``anthropic``, ``local`` or ``off``. ``auto`` picks ``local`` when
  ``SUTRA_AI_LOCAL_URL`` is set, ``anthropic`` when an API key is set, and otherwise ``off``: explanations are then
  written from fixed rules and say so.
* ``SUTRA_AI_LOCAL_URL`` (for example ``http://127.0.0.1:11434/v1``), ``SUTRA_AI_LOCAL_MODEL``,
  ``SUTRA_AI_LOCAL_KEY`` (optional) for a model inside the customer's network.
* ``SUTRA_AI_EXPLAIN_MODEL`` (default ``claude-sonnet-5-5``), ``SUTRA_AI_EXPLAIN_EFFORT`` (default ``medium``;
  ``none`` leaves it out), ``SUTRA_AI_ATTEMPTS`` (default 2), ``SUTRA_AI_TIMEOUT`` (seconds, default 300).
* ``SUTRA_AI_EXPLAIN=off`` turns explanations to rule-written text while leaving other AI features alone.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping

from .clients import AnthropicClient, LocalClient, ModelUnavailable

DEFAULT_MODEL = "claude-sonnet-5-5"
PROVIDERS = ("auto", "anthropic", "local", "off")


@dataclass(frozen=True)
class ExplainConfig:
    provider: str = "off"  # resolved: anthropic | local | off
    model: str = DEFAULT_MODEL
    effort: str | None = "medium"
    attempts: int = 2
    timeout: float = 300.0
    max_tokens: int = 4000
    local_url: str = ""
    local_model: str = ""
    local_key: str = ""
    api_key: str = ""
    reason: str = ""  # why the provider is off, when it is

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ExplainConfig:
        env = os.environ if env is None else env

        def get(name: str, default: str = "") -> str:
            return (env.get(name) or default).strip()

        def number(name: str, default, kind):
            v = get(name)
            try:
                return kind(v) if v else default
            except ValueError:
                raise ValueError(f"{name} must be a number, got {v!r}") from None

        wanted = get("SUTRA_AI_PROVIDER", "auto").lower()
        if wanted not in PROVIDERS:
            raise ValueError(f"SUTRA_AI_PROVIDER must be one of {', '.join(PROVIDERS)}, got {wanted!r}")
        key = get("ANTHROPIC_API_KEY") or get("ANTHROPIC_AUTH_TOKEN")
        local_url = get("SUTRA_AI_LOCAL_URL")
        provider, reason = wanted, ""
        if get("SUTRA_AI_EXPLAIN").lower() in ("off", "0", "false", "no"):
            provider, reason = "off", "AI explanations are switched off (SUTRA_AI_EXPLAIN=off)"
        elif wanted == "auto":
            provider = "local" if local_url else "anthropic" if key else "off"
            reason = "" if provider != "off" else (
                "no AI model is configured (set SUTRA_AI_LOCAL_URL or ANTHROPIC_API_KEY)")
        elif wanted == "off":
            reason = "AI is switched off (SUTRA_AI_PROVIDER=off)"
        elif wanted == "anthropic" and not key:
            provider, reason = "off", "SUTRA_AI_PROVIDER=anthropic but no ANTHROPIC_API_KEY is set"
        elif wanted == "local" and not (local_url and get("SUTRA_AI_LOCAL_MODEL")):
            provider, reason = "off", "SUTRA_AI_PROVIDER=local needs SUTRA_AI_LOCAL_URL and SUTRA_AI_LOCAL_MODEL"
        effort = get("SUTRA_AI_EXPLAIN_EFFORT", "medium").lower()
        return cls(provider=provider, model=get("SUTRA_AI_EXPLAIN_MODEL", DEFAULT_MODEL),
                   effort=None if effort == "none" else effort, attempts=number("SUTRA_AI_ATTEMPTS", 2, int),
                   timeout=number("SUTRA_AI_TIMEOUT", 300.0, float), local_url=local_url,
                   local_model=get("SUTRA_AI_LOCAL_MODEL"), local_key=get("SUTRA_AI_LOCAL_KEY"), api_key=key,
                   reason=reason)

    @property
    def air_gapped_safe(self) -> bool:
        """True when no prompt can leave the customer's network: the model is local, or there is none."""
        return self.provider != "anthropic"

    def build_client(self) -> tuple[Any, str]:
        """The model client, or (None, why not)."""
        if self.provider == "off":
            return None, self.reason
        try:
            if self.provider == "local":
                return LocalClient(self.local_url, self.local_model, self.local_key, self.timeout), ""
            return AnthropicClient(self.model, self.api_key, self.timeout, self.effort), ""
        except (ModelUnavailable, ValueError) as e:
            return None, str(e)
