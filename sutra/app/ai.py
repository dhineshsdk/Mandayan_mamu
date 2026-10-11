"""AI in the app: one place that reads the environment, builds the models and keeps explanations.

Three jobs use a model, and all three fall back to fixed rules when no model is available:

* patch-job drafts (``sutra_patchdraft``), wired in ``drafter()``;
* root-cause explanations and the board briefing (``sutra_explain``), kept in ``ai_explanations``;
* the reader that labels raw finding text, when ``SUTRA_AI_READER=model`` (default ``rules``: no finding text is
  sent to any model unless an administrator turns this on).

Routing, SSVC, rupee risk and approval levels never depend on a model. Nothing here writes to a job, a finding or a
risk number.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Mapping
from dataclasses import replace
from datetime import timedelta
from urllib.parse import urlsplit

from sqlalchemy import delete, select
from sqlalchemy.orm import Session
from sutra_explain import (
    ExplainConfig,
    Explainer,
    LocalClient,
    MessagesShim,
    ModelReader,
    RuleReader,
    board_facts,
    root_cause_facts,
)
from sutra_explain.builders import read_findings
from sutra_patchdraft import DrafterConfig, PatchDrafter

from .egress import EgressGuard
from .models import AiExplanation, utcnow
from .security import audit

KEEP_DAYS = 90


ANTHROPIC_HOST = "api.anthropic.com"


def drafter(cfg: ExplainConfig, env: Mapping[str, str] | None = None) -> PatchDrafter:
    """The patch-job drafter that matches the AI settings: Claude, a local model, or templates only."""
    env = os.environ if env is None else env
    if cfg.provider == "off":
        return PatchDrafter(config=replace(DrafterConfig.from_env(env), enabled=False), env={})
    if cfg.provider == "local":
        client = LocalClient(cfg.local_url, cfg.local_model, cfg.local_key, cfg.timeout)
        conf = replace(DrafterConfig.from_env(env), model=cfg.local_model, effort=None, adaptive_thinking=False,
                       server_fallbacks=False)
        return PatchDrafter(config=conf, client=MessagesShim(client))
    return PatchDrafter(config=DrafterConfig.from_env(env), env=env)


def blocked_by_policy(cfg: ExplainConfig, guard: EgressGuard | None) -> ExplainConfig:
    """Switch the model off, with the reason, when the outbound policy would refuse its endpoint."""
    if guard is None or guard.policy == "open" or cfg.provider == "off":
        return cfg
    host = ANTHROPIC_HOST if cfg.provider == "anthropic" else (urlsplit(cfg.local_url).hostname or "")
    if guard.host_allowed(host):
        return cfg
    return replace(cfg, provider="off", reason=f"{host} is not on this server's outbound allow-list "
                                               f"(SUTRA_EGRESS_ALLOW), so no prompt can be sent there")


def scope_key(asset_ids: set[str]) -> str:
    return hashlib.sha256("\n".join(sorted(asset_ids)).encode()).hexdigest()


class AiService:
    def __init__(self, config: ExplainConfig | None = None, explainer: Explainer | None = None,
                 env: Mapping[str, str] | None = None, guard: EgressGuard | None = None):
        env = os.environ if env is None else env
        self.guard = guard
        self.config = blocked_by_policy(config or ExplainConfig.from_env(env), guard)
        self.explainer = explainer or Explainer.from_config(self.config)
        self.reader_mode = (env.get("SUTRA_AI_READER") or "rules").strip().lower()
        if self.reader_mode not in ("rules", "model"):
            raise ValueError("SUTRA_AI_READER must be rules or model")
        self._lock = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}

    # ----- status -----
    @property
    def config_key(self) -> str:
        c = self.config
        return f"{c.provider}:{c.local_model if c.provider == 'local' else c.model}:{self.reader_mode}"

    def status(self, drafting_ai: bool) -> dict:
        c = self.config
        host = urlsplit(c.local_url).netloc if c.provider == "local" else ""
        return {
            "provider": c.provider, "model": c.local_model if c.provider == "local" else
            (c.model if c.provider == "anthropic" else ""),
            "local_endpoint": host, "reader": self.reader_mode, "explanations_by_model": self.explainer.ai_available,
            "drafting_by_model": drafting_ai, "reason": c.reason or self.explainer.unavailable,
            "prompts_leave_the_network": c.provider == "anthropic",
            "egress": self.guard.status() if self.guard else None,
            "note": ("Prompts go to the Anthropic API. For data that must stay inside the customer's network, set "
                     "SUTRA_AI_LOCAL_URL and SUTRA_AI_LOCAL_MODEL, or SUTRA_AI_PROVIDER=off."
                     if c.provider == "anthropic" else
                     "No prompt leaves the customer's network." if c.provider == "local" else
                     "No model is used. Explanations and drafts come from fixed rules."),
        }

    # ----- explanations -----
    def _reader(self):
        if self.reader_mode == "model" and self.explainer.client is not None:
            return ModelReader(self.explainer.client)
        return RuleReader()

    def _key_lock(self, key: str) -> threading.Lock:
        with self._lock:
            return self._locks.setdefault(key, threading.Lock())

    def _cached(self, db: Session, kind: str, subject: str, scope: str, facts, make, actor, ip: str) -> dict:
        digest = hashlib.sha256(json.dumps(
            {"facts": facts.for_model(), "labels": {r: n.label for r, n in facts.nodes.items()}},
            sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        where = (AiExplanation.kind == kind, AiExplanation.subject == subject, AiExplanation.scope_key == scope,
                 AiExplanation.facts_hash == digest, AiExplanation.config_key == self.config_key)
        with self._key_lock(f"{kind}|{subject}|{scope}|{digest}"):  # one model call per explanation at a time
            row = db.scalars(select(AiExplanation).where(*where)).first()
            if row:
                return {**row.result, "cached": True, "generated_at": row.created_at.isoformat()}
            result = make()
            out = result.to_dict(facts)
            audit(db, "ai.explained", actor, kind, subject, ip, source=result.source, model=result.model,
                  fallback=bool(result.fallback_reason), scope=scope[:12])
            # A rule-written fallback caused by a model failure is not kept, so the next view tries the model again.
            if result.source == "ai" or not self.explainer.ai_available:
                db.add(AiExplanation(kind=kind, subject=subject, scope_key=scope, facts_hash=digest,
                                     config_key=self.config_key, source=result.source, result=out))
                db.execute(delete(AiExplanation).where(AiExplanation.created_at < utcnow() - timedelta(days=KEEP_DAYS)))
            db.commit()
            return {**out, "cached": False, "generated_at": utcnow().isoformat()}

    def root_cause(self, db: Session, payload: dict, rc_id: str, scope: str, actor, ip: str) -> dict:
        facts = root_cause_facts(payload, rc_id, reader=self._reader() if self.reader_mode == "model" else None)
        return self._cached(db, "root_cause", rc_id, scope, facts,
                            lambda: self.explainer.explain_root_cause(facts), actor, ip)

    def briefing(self, db: Session, payload: dict, unowned: int, scope: str, actor, ip: str) -> dict:
        top = [fid for rc in payload["root_causes"][:5] for fid in rc["finding_ids"]]
        typed = read_findings(payload, top)  # rules: the model never decides what looks like an instruction
        facts = board_facts(payload, unowned=unowned, typed=typed)
        return self._cached(db, "briefing", payload["org"][:120], scope, facts,
                            lambda: self.explainer.brief_board(facts), actor, ip)
