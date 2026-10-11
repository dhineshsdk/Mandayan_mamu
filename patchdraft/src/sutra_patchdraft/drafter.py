"""Drafts a patch job with Claude, checks it, and falls back to the template when it cannot use the result.

The model sees the root cause, hosts and findings as escaped, untrusted data, answers in a fixed JSON schema for the
job's lane, and its answer must pass ``grounding.validate``. A rejected draft is retried once with the reasons; if
it still fails, or the API is unavailable or declines, the template drafter writes the job instead and the draft
records why. The approval route is never an input or an output here.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, replace
from typing import Any, Mapping

from .draft import PatchJobDraft, render
from .facts import Facts, build_facts, corpus
from .grounding import validate
from .inputs import DraftInput
from .prompt import SYSTEM_PROMPT, user_message
from .schema import schema_for
from .template import template_raw

log = logging.getLogger("sutra_patchdraft")

DEFAULT_MODEL = "claude-opus-5-5"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
EFFORTS = ("low", "medium", "high", "xhigh", "max")


@dataclass(frozen=True)
class DrafterConfig:
    enabled: bool = True
    model: str = DEFAULT_MODEL
    effort: str | None = "high"  # None leaves effort out, for models that do not take it
    adaptive_thinking: bool = True
    max_tokens: int = 16000
    timeout_seconds: float = 300.0
    max_retries: int = 2  # SDK retries for rate limits, overload and connection errors
    max_attempts: int = 2  # model drafts tried before the template takes over
    server_fallbacks: bool = True  # on a safety decline, the API re-runs the request on its recommended model
    max_findings_in_prompt: int = 400

    def __post_init__(self):
        if self.effort is not None and self.effort not in EFFORTS:
            raise ValueError(f"effort must be one of {', '.join(EFFORTS)} or None, got {self.effort!r}")
        if self.max_attempts < 1 or self.max_tokens < 1024 or self.max_findings_in_prompt < 1:
            raise ValueError("max_attempts must be at least 1, max_tokens at least 1024, "
                             "max_findings_in_prompt at least 1")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "DrafterConfig":
        """Settings from ``SUTRA_AI_*`` variables; anything unset keeps its default."""
        env = os.environ if env is None else env

        def flag(name: str, default: bool) -> bool:
            value = env.get(name, "").strip().lower()
            if not value:
                return default
            if value in ("1", "true", "yes", "on"):
                return True
            if value in ("0", "false", "no", "off"):
                return False
            raise ValueError(f"{name} must be on or off, got {value!r}")

        def number(name: str, default, kind):
            value = env.get(name, "").strip()
            try:
                return kind(value) if value else default
            except ValueError:
                raise ValueError(f"{name} must be a number, got {value!r}") from None

        effort = env.get("SUTRA_AI_EFFORT", "").strip().lower() or "high"
        return cls(
            enabled=flag("SUTRA_AI_DRAFTING", True),
            model=env.get("SUTRA_AI_MODEL", "").strip() or DEFAULT_MODEL,
            effort=None if effort == "none" else effort,
            adaptive_thinking=flag("SUTRA_AI_ADAPTIVE_THINKING", True),
            max_tokens=number("SUTRA_AI_MAX_TOKENS", 16000, int),
            timeout_seconds=number("SUTRA_AI_TIMEOUT", 300.0, float),
            max_attempts=number("SUTRA_AI_ATTEMPTS", 2, int),
            server_fallbacks=flag("SUTRA_AI_SERVER_FALLBACKS", True),
        )


class _Unusable(Exception):
    """The model's reply cannot be used as a draft (cut off, not JSON); worth one more try."""


class _Declined(Exception):
    """The API or model will not produce a draft for this input; go straight to the template."""


def _api_errors() -> tuple[type[BaseException], ...]:
    try:
        import anthropic
    except ImportError:
        return ()
    return (anthropic.APIError,)


def _default_client(config: DrafterConfig, env: Mapping[str, str]) -> tuple[Any, str | None]:
    if not config.enabled:
        return None, "AI drafting is switched off"
    if not (env.get("ANTHROPIC_API_KEY") or env.get("ANTHROPIC_AUTH_TOKEN")):
        return None, "AI drafting is not configured: no ANTHROPIC_API_KEY is set"
    try:
        import anthropic
    except ImportError:
        return None, "AI drafting needs the anthropic package: pip install 'sutra-patchdraft[ai]'"
    return anthropic.Anthropic(timeout=config.timeout_seconds, max_retries=config.max_retries), None


class PatchDrafter:
    """Turns a ``DraftInput`` into a ``PatchJobDraft``. Never raises for model trouble; it falls back instead."""

    def __init__(self, config: DrafterConfig | None = None, client: Any = None,
                 env: Mapping[str, str] | None = None):
        env = os.environ if env is None else env
        self.config = config or DrafterConfig.from_env(env)
        self._client, self._unavailable = (client, None) if client is not None else _default_client(self.config,
                                                                                                    env)

    @property
    def ai_available(self) -> bool:
        return self._client is not None

    def draft(self, inp: DraftInput) -> PatchJobDraft:
        facts = build_facts(inp)
        lane = "ot" if inp.is_ot else "it"
        corp = corpus(inp)
        if self._client is None:
            return self._template(inp, facts, lane, corp, self._unavailable, attempts=0)

        rejected: list[str] = []
        reason = ""
        for attempt in range(1, self.config.max_attempts + 1):
            try:
                raw, served_by, warnings = self._ask(inp, facts, lane, rejected)
            except _Declined as e:
                reason = str(e)
                break
            except _Unusable as e:
                rejected, reason = [str(e)], f"The model's draft was unusable: {e}"
                log.warning("%s attempt %d: %s", inp.root_cause.rc_id, attempt, e)
                continue
            except (*_api_errors(), *getattr(self._client, "api_errors", ())) as e:
                reason = f"The Claude API call failed ({type(e).__name__})"
                log.warning("%s: %s: %s", inp.root_cause.rc_id, reason, e)
                break
            errors = validate(raw, lane, facts, corp)
            if not errors:
                return render(raw, lane, facts, inp, source="ai", model=served_by, attempts=attempt,
                              warnings=warnings)
            rejected = errors
            reason = (f"The model's draft failed Sutra's checks after {attempt} attempt(s): "
                      + "; ".join(errors[:3]) + (f" (and {len(errors) - 3} more)" if len(errors) > 3 else ""))
            log.warning("%s attempt %d rejected: %s", inp.root_cause.rc_id, attempt, "; ".join(errors[:10]))
        return self._template(inp, facts, lane, corp, reason, attempts=self.config.max_attempts)

    def _template(self, inp: DraftInput, facts: Facts, lane: str, corp: str, reason: str | None,
                  attempts: int) -> PatchJobDraft:
        raw = template_raw(inp, facts, lane)
        errors = validate(raw, lane, facts, corp)
        if errors:  # a bug in the template, not bad input: fail loudly
            raise RuntimeError(f"template draft for {inp.root_cause.rc_id} failed validation: {errors}")
        if reason:
            log.info("%s drafted from the template: %s", inp.root_cause.rc_id, reason)
        return render(raw, lane, facts, inp, source="template", attempts=attempts, fallback_reason=reason)

    def _ask(self, inp: DraftInput, facts: Facts, lane: str, rejected: list[str]) -> tuple[dict, str, list[str]]:
        cfg = self.config
        output_config: dict = {"format": {"type": "json_schema", "schema": schema_for(lane)}}
        if cfg.effort:
            output_config["effort"] = cfg.effort
        kwargs: dict = {
            "model": cfg.model,
            "max_tokens": cfg.max_tokens,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user",
                          "content": user_message(inp, facts, lane, cfg.max_findings_in_prompt, rejected)}],
            "output_config": output_config,
        }
        if cfg.adaptive_thinking:
            kwargs["thinking"] = {"type": "adaptive"}
        if cfg.server_fallbacks:
            response = self._client.beta.messages.create(**kwargs, betas=[FALLBACK_BETA], fallbacks="default")
        else:
            response = self._client.messages.create(**kwargs)

        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None) if details else None
            raise _Declined("The model declined to draft this job" + (f" ({category})" if category else ""))
        if response.stop_reason == "max_tokens":
            raise _Unusable("the draft was cut off at the token limit; write a shorter draft")

        texts: list[str] = []
        warnings: list[str] = []
        for block in response.content:
            kind = getattr(block, "type", None)
            if kind == "fallback":  # output before a switch point came from a model that declined
                texts = []
            elif kind == "text":
                texts.append(block.text)
        served_by = getattr(response, "model", None) or cfg.model
        if served_by != cfg.model:
            warnings.append(f"Drafted by {served_by} after {cfg.model} declined")
        if not texts:
            raise _Unusable("the reply had no draft in it")
        try:
            raw = json.loads("".join(texts))
        except json.JSONDecodeError:
            raise _Unusable("the reply was not valid JSON") from None
        return raw, served_by, warnings


def draft_patch_job(inp: DraftInput, *, config: DrafterConfig | None = None, client: Any = None) -> PatchJobDraft:
    """One-off convenience wrapper around ``PatchDrafter(config, client).draft(inp)``."""
    return PatchDrafter(config=config, client=client).draft(inp)


def template_only() -> PatchDrafter:
    """A drafter that never calls a model, for air-gapped installs and tests."""
    return PatchDrafter(config=replace(DrafterConfig(), enabled=False), env={})
