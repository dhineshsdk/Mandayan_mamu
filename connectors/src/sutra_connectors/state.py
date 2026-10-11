"""Checkpoints for incremental pulls, and the one function that runs a pull safely.

A checkpoint records when the last successful pull started. The next pull asks the scanner only for what changed
since then, minus a safety overlap, because scanners index results some time after a scan finishes. Overlap means
a few detections arrive twice; downstream dedupe keys on ``ScannerFinding.record_id``, so that is harmless.

The checkpoint moves only after every record of a pull has been handed to the caller's sink. A pull that fails
half-way leaves the old checkpoint, and the next run repeats it.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol

from .models import ScannerFinding, ScannerHost


class Connector(Protocol):
    """What :func:`sync` needs from a connector. All three connectors implement it."""

    @property
    def checkpoint_key(self) -> str: ...

    def iter_findings(self, since: datetime | None = None) -> Iterator[ScannerFinding]: ...

    def iter_hosts(self, since: datetime | None = None) -> Iterator[ScannerHost]: ...


class CheckpointStore(Protocol):
    def get(self, key: str) -> dict | None: ...

    def put(self, key: str, value: dict) -> None: ...


class MemoryCheckpointStore:
    def __init__(self) -> None:
        self.data: dict[str, dict] = {}

    def get(self, key: str) -> dict | None:
        return self.data.get(key)

    def put(self, key: str, value: dict) -> None:
        self.data[key] = dict(value)


class JsonFileCheckpointStore:
    """Checkpoints in one JSON file, written atomically (temp file, then rename) with owner-only permissions."""

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)

    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}

    def get(self, key: str) -> dict | None:
        return self._load().get(key)

    def put(self, key: str, value: dict) -> None:
        data = self._load()
        data[key] = value
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=self.path.name, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, sort_keys=True)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise


@dataclass(frozen=True)
class SyncReport:
    checkpoint_key: str
    started_at: datetime
    since: datetime | None  # None means a full pull
    findings: int
    hosts: int


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def sync(
    connector: Connector,
    store: CheckpointStore,
    on_finding: Callable[[ScannerFinding], None],
    on_host: Callable[[ScannerHost], None] | None = None,
    *,
    full: bool = False,
    overlap: timedelta = timedelta(hours=1),
    clock: Callable[[], datetime] = _utcnow,
) -> SyncReport:
    """Pull findings (and hosts, when ``on_host`` is given) changed since the last successful pull.

    ``full=True`` ignores the checkpoint and pulls everything the connector's full-pull rules return.
    """
    key = connector.checkpoint_key
    started = clock()
    since = None
    if not full:
        saved = store.get(key)
        if saved and saved.get("last_success_started_at"):
            since = datetime.fromisoformat(saved["last_success_started_at"]) - overlap
    n_hosts = 0
    if on_host is not None:
        for host in connector.iter_hosts(since):
            on_host(host)
            n_hosts += 1
    n_findings = 0
    for finding in connector.iter_findings(since):
        on_finding(finding)
        n_findings += 1
    store.put(key, {"last_success_started_at": started.isoformat(), "findings": n_findings, "hosts": n_hosts,
                    "full": since is None})
    return SyncReport(key, started, since, n_findings, n_hosts)

