"""Scheduled pulls from scanner APIs (``sutra_connectors``), so nobody has to export a file.

A pull reads every enabled scanner connection in full (all open detections, and every host the scanner knows), then
analyses the result exactly like an uploaded export and makes it the current import. Details:

- **All or nothing.** If any enabled connection fails, nothing is imported and the pull is recorded as failed. A
  partial pull would drop one scanner's findings and a rescan check would then wrongly close jobs as fixed.
- **Hosts prove a scan.** Every host the scanner reports as assessed is passed on as a scan-information row, which
  is how exported files show that a host was scanned. Without it a fully patched host would look unscanned and its
  jobs could never close.
- **The asset register** (CMDB file) is carried over from the latest import that had one.
- **Full pulls, not deltas.** Each import is a whole picture of open findings, which is what the history, the
  "what changed" view and verified closure compare. The connectors' incremental mode is not used here.
- **Schedule.** Once a day at the hour set under Import data (India time), when switched on. Admins can also start
  a pull by hand. Only one pull runs at a time.
"""

from __future__ import annotations

import logging
import secrets
import threading
from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from .. import ingest
from . import drafting, vault
from .config import Settings
from .models import Dataset, ScannerConnection, ScanPull, Setting, utcnow
from .security import audit

log = logging.getLogger("sutra.scanpull")
KINDS = {
    "qualys": {"label": "Qualys VMDR", "user": "API user name", "secret": "Password", "default_url": "",
               "url_hint": "https://qualysapi.qg1.apps.qualys.in"},
    "tenable_vm": {"label": "Tenable Vulnerability Management", "user": "Access key", "secret": "Secret key",
                   "default_url": "https://cloud.tenable.com", "url_hint": "https://cloud.tenable.com"},
    "tenable_sc": {"label": "Tenable Security Center", "user": "Access key", "secret": "Secret key",
                   "default_url": "", "url_hint": "https://sc.plant.example.in"},
}
DEFAULT_SCHEDULE = {"enabled": False, "hour": 2}
CHECK_SECONDS = 300


def build(conn: ScannerConnection, secret: str, transport=None):
    """A connector for ``conn``. ``transport`` is for tests."""
    from sutra_connectors import QualysConnector, TenableSCConnector, TenableVMConnector

    verify: bool | str = conn.ca_bundle or True
    extra = {"transport": transport} if transport is not None else {}
    if conn.kind == "qualys":
        return QualysConnector(conn.base_url, conn.username, secret, verify=verify, **extra)
    if conn.kind == "tenable_vm":
        return TenableVMConnector(conn.username, secret, base_url=conn.base_url, verify=verify, **extra)
    if conn.kind == "tenable_sc":
        return TenableSCConnector(conn.base_url, conn.username, secret, verify=verify, **extra)
    raise ValueError(f"Unknown scanner kind {conn.kind!r}.")


def schedule(db: Session) -> dict:
    s = db.get(Setting, "scan_schedule")
    return {**DEFAULT_SCHEDULE, **(dict(s.value) if s else {})}


def connection_json(c: ScannerConnection) -> dict:
    return {"id": c.id, "kind": c.kind, "kind_label": KINDS[c.kind]["label"], "name": c.name, "base_url": c.base_url,
            "username": c.username, "has_secret": bool(c.secret), "ca_bundle": c.ca_bundle, "enabled": c.enabled,
            "updated": c.updated_at.isoformat(timespec="seconds")}


def pull_json(p: ScanPull) -> dict:
    return {"id": p.id, "trigger": p.trigger, "status": p.status, "results": p.results, "error": p.error,
            "started": p.started_at.isoformat(timespec="seconds"),
            "finished": p.finished_at.isoformat(timespec="seconds") if p.finished_at else None,
            "dataset": p.dataset_id}


def _host_rows(conn_kind: str, hosts) -> list[dict]:
    """Scan-information rows for hosts the scanner has assessed: they prove the host was scanned."""
    rows = []
    for h in hosts:
        if h.last_seen is None or not (h.ip or h.hostname):
            continue
        rows.append(dict(scanner=h.scanner, ref=f"host {h.host_id}", file=h.source, row=f"host:{h.host_id}",
                         ip=h.ip.strip(), host=(h.hostname or "").split(".")[0].strip().lower(), os=h.os,
                         title=f"Host assessed by {h.scanner}", severity="info", cvss=None, cves=[], port="",
                         evidence="", solution="", first=h.first_seen.date() if h.first_seen else None,
                         last=h.last_seen.date(), package="", installed="", fixed="", control="", credential_fp="",
                         kind="info"))
    return rows


class Puller:
    """Runs pulls one at a time on a background thread, and on a daily schedule."""

    def __init__(self, app, transport=None, factory: Callable | None = None):
        self.app = app
        self.transport = transport
        self.factory = factory or build
        self._lock = threading.Lock()
        self._stop = threading.Event()

    @property
    def settings(self) -> Settings:
        return self.app.state.settings

    @property
    def sessions(self) -> sessionmaker:
        return self.app.state.sessionmaker

    def busy(self) -> bool:
        return self._lock.locked()

    def start(self, trigger: str, user_id: int | None, background: bool = True) -> int:
        """Record a pull and run it. Raises RuntimeError if one is already running."""
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("A pull is already running.")
        try:
            with self.sessions() as db:
                if not db.scalars(select(ScannerConnection).where(ScannerConnection.enabled.is_(True))).first():
                    raise ValueError("Add and switch on at least one scanner connection first.")
                pull = ScanPull(trigger=trigger, started_by=user_id, results=[])
                db.add(pull)
                db.commit()
                pull_id = pull.id
        except Exception:
            self._lock.release()
            raise
        if background:
            threading.Thread(target=self._run_locked, args=(pull_id,), name="sutra-scanpull", daemon=True).start()
        else:
            self._run_locked(pull_id)
        return pull_id

    def _run_locked(self, pull_id: int) -> None:
        try:
            self.run(pull_id)
        except Exception:
            log.exception("pull %s crashed", pull_id)
        finally:
            self._lock.release()

    def run(self, pull_id: int) -> None:
        with self.sessions() as db:
            pull = db.get(ScanPull, pull_id)
            conns = list(db.scalars(select(ScannerConnection).where(ScannerConnection.enabled.is_(True))
                                    .order_by(ScannerConnection.id)))
            dest = self.settings.workspace / "datasets" / f"api-{secrets.token_hex(4)}"
            dest.mkdir(parents=True)
            files, results, failed = [], [], False
            for conn in conns:
                result = {"connection": conn.id, "name": conn.name, "kind": conn.kind, "findings": 0, "hosts": 0,
                          "error": ""}
                try:
                    secret = vault.open_(self.settings.secret_key, conn.secret)
                    files.append(self._pull_one(conn, secret, dest, result))
                except Exception as e:  # each connector raises errors without credentials in them
                    failed = True
                    result["error"] = f"{type(e).__name__}: {e}"[:500]
                    log.warning("pull %s: %s failed: %s", pull_id, conn.name, result["error"])
                results.append(result)
            pull.results = results
            if not failed:
                cmdb = self._latest_cmdb(db)
                if cmdb:
                    files.append(cmdb)
                try:
                    org = self._org(db)
                    ds = self.app.state.analysis.activate(db, files, org, "api", pull.started_by)
                    pull.dataset_id = ds.id
                except (Exception, SystemExit) as e:  # the pipeline exits when there are no findings at all
                    db.rollback()
                    pull = db.get(ScanPull, pull_id)
                    pull.results = results
                    failed = True
                    pull.error = f"The pulled data could not be analysed: {e}"[:2000]
            elif not pull.error:
                pull.error = "Nothing was imported because a scanner connection failed."
            pull.status = "failed" if failed else "ok"
            pull.finished_at = utcnow()
            audit(db, "data.pull", None, "scan_pull", pull.id, status=pull.status, trigger=pull.trigger,
                  dataset=pull.dataset_id,
                  results=[{k: r[k] for k in ("name", "findings", "hosts", "error")} for r in results])
            db.commit()

    def _pull_one(self, conn: ScannerConnection, secret: str, dest, result: dict) -> dict:
        from sutra_connectors.sutra_rows import to_sutra_rows

        connector = self.factory(conn, secret, self.transport)
        try:
            findings = list(connector.iter_findings())
            hosts = list(connector.iter_hosts())
        finally:
            close = getattr(connector, "close", None)
            if close:
                close()
        rows = list(to_sutra_rows(findings)) + _host_rows(conn.kind, hosts)
        result["findings"], result["hosts"] = sum(1 for r in rows if r["kind"] != "info"), len(hosts)
        name = f"{conn.kind}-{conn.id}.jsonl"
        ingest.write_rows(dest / name, connector.source, rows)
        return {"path": str(dest / name), "name": f"{conn.name} ({KINDS[conn.kind]['label']} API)", "format": "rows"}

    @staticmethod
    def _latest_cmdb(db: Session) -> dict | None:
        for ds in db.scalars(select(Dataset).order_by(Dataset.id.desc())):
            for f in ds.files or []:
                if f.get("format") == "cmdb":
                    return f
        return None

    @staticmethod
    def _org(db: Session) -> str:
        cur = db.scalars(select(Dataset).where(Dataset.is_current.is_(True))).first()
        return cur.org_name if cur else ""

    # ---------- schedule ----------

    def due(self, db: Session, now: datetime) -> bool:
        """Switched on, past today's hour in India, and no pull started since then."""
        cfg = schedule(db)
        if not cfg["enabled"]:
            return False
        local = now.replace(tzinfo=UTC).astimezone(drafting.IST)
        if local.hour < int(cfg["hour"]):
            return False
        slot = local.replace(hour=int(cfg["hour"]), minute=0, second=0, microsecond=0)
        slot_utc = slot.astimezone(UTC).replace(tzinfo=None)
        last = db.scalars(select(ScanPull.started_at).order_by(ScanPull.id.desc())).first()
        return last is None or last < slot_utc

    def tick(self, now: datetime | None = None) -> int | None:
        with self.sessions() as db:
            if not self.due(db, now or utcnow()):
                return None
            if not db.scalars(select(ScannerConnection).where(ScannerConnection.enabled.is_(True))).first():
                return None
        try:
            return self.start("schedule", None, background=False)
        except RuntimeError:
            return None

    def start_schedule(self) -> None:
        threading.Thread(target=self._loop, name="sutra-scan-schedule", daemon=True).start()

    def _loop(self) -> None:
        while not self._stop.wait(CHECK_SECONDS):
            try:
                self.tick()
            except Exception:
                log.exception("scheduled pull failed")

    def stop(self) -> None:
        self._stop.set()


def last_pull(db: Session) -> ScanPull | None:
    return db.scalars(select(ScanPull).order_by(ScanPull.id.desc())).first()


def fail_interrupted(db: Session) -> int:
    """At start-up: a pull still marked running was cut off by a restart. The caller commits."""
    n = 0
    for p in db.scalars(select(ScanPull).where(ScanPull.status == "running")):
        p.status, p.finished_at, p.error = "failed", utcnow(), "Sutra restarted while this pull was running."
        n += 1
    return n
