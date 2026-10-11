import os
import stat
from datetime import datetime, timedelta, timezone

import pytest

from sutra_connectors.state import JsonFileCheckpointStore, MemoryCheckpointStore, sync

T0 = datetime(2026, 10, 1, 6, 0, tzinfo=timezone.utc)


class FakeConnector:
    checkpoint_key = "fake:scanner.example"

    def __init__(self, fail=False):
        self.fail = fail
        self.calls = []

    def iter_hosts(self, since=None):
        self.calls.append(("hosts", since))
        yield "h1"

    def iter_findings(self, since=None):
        self.calls.append(("findings", since))
        yield "f1"
        if self.fail:
            raise RuntimeError("connection lost")
        yield "f2"


def test_first_pull_is_full_then_incremental_with_overlap():
    store, got = MemoryCheckpointStore(), []
    c = FakeConnector()
    r1 = sync(c, store, got.append, got.append, clock=lambda: T0)
    assert r1.since is None and r1.findings == 2 and r1.hosts == 1
    r2 = sync(c, store, got.append, clock=lambda: T0 + timedelta(days=1))
    assert r2.since == T0 - timedelta(hours=1)
    assert c.calls[-1] == ("findings", T0 - timedelta(hours=1))
    assert store.get(c.checkpoint_key)["last_success_started_at"] == (T0 + timedelta(days=1)).isoformat()


def test_failed_pull_keeps_old_checkpoint():
    store = MemoryCheckpointStore()
    sync(FakeConnector(), store, lambda f: None, clock=lambda: T0)
    with pytest.raises(RuntimeError):
        sync(FakeConnector(fail=True), store, lambda f: None, clock=lambda: T0 + timedelta(days=1))
    assert store.get(FakeConnector.checkpoint_key)["last_success_started_at"] == T0.isoformat()


def test_full_ignores_checkpoint():
    store = MemoryCheckpointStore()
    sync(FakeConnector(), store, lambda f: None, clock=lambda: T0)
    assert sync(FakeConnector(), store, lambda f: None, full=True, clock=lambda: T0).since is None


def test_json_store_round_trip_and_permissions(tmp_path):
    path = tmp_path / "state" / "checkpoints.json"
    s = JsonFileCheckpointStore(path)
    assert s.get("a") is None
    s.put("a", {"x": 1})
    s.put("b", {"y": 2})
    assert JsonFileCheckpointStore(path).get("a") == {"x": 1}
    assert [p.name for p in path.parent.iterdir()] == ["checkpoints.json"]  # no temp files left behind
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
