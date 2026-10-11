"""Read-only configuration collection from firewalls and switches (``sutra_connectors`` collectors).

- **What is kept.** Each distinct configuration of a device, with secrets already masked by the collector. A
  collection that finds the same configuration as last time (ignoring lines the device rewrites by itself) only
  moves its "last seen" time, so the history is a list of real changes. A switch's ARP and MAC tables are kept with
  the latest snapshot.
- **Devices are independent.** One device failing does not stop the others; its error is shown on the device.
- **SSH host keys** are pinned the first time a device answers, and a different key later stops collection from it
  until an admin clears the pinned key.
- **Schedule.** Once a day, at the same hour as the scanner pulls (Import data), when that schedule is switched on.
  Admins and VM analysts can also collect by hand. Only one collection runs at a time.
"""

from __future__ import annotations

import difflib
import ipaddress
import logging
import re
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from . import drafting, scanpull, vault
from .config import Settings
from .models import ConfigSnapshot, NetworkDevice, utcnow
from .security import audit

log = logging.getLogger("sutra.netconfig")

KINDS = {
    "fortigate": {"label": "Fortinet FortiGate", "transport": "api", "user": "", "secret": "REST API token",
                  "address_hint": "https://fw1.plant.example.in"},
    "panos": {"label": "Palo Alto Networks firewall (PAN-OS)", "transport": "api", "user": "",
              "secret": "XML API key", "address_hint": "https://pa-dc.example.in"},
    "cisco_ios": {"label": "Cisco IOS or IOS-XE switch or router (SSH)", "transport": "ssh",
                  "user": "SSH user name", "secret": "Password",
                  "address_hint": "10.20.0.2 or sw1.plant.example.in:22"},
}
DIFF_LINE_LIMIT = 5000
_HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,62}[A-Za-z0-9])?)*$")


def check_address(kind: str, address: str) -> str:
    """The device address in the form its kind needs. Raises ValueError with a message for the admin."""
    address = address.strip()
    if KINDS[kind]["transport"] == "api":
        url = address.rstrip("/")
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname or parts.path not in ("", "/") or parts.query:
            raise ValueError("The address must be the device's https:// management URL with no path, for example "
                             f"{KINDS[kind]['address_hint']}.")
        return url
    host, port = split_host(address)
    return host if port == 22 else (f"[{host}]:{port}" if ":" in host else f"{host}:{port}")


def split_host(address: str) -> tuple[str, int]:
    """``host``, ``host:port``, ``[v6]:port`` or a bare IPv6 address, as (host, port)."""
    bad = ValueError("The address must be a host name or IP address, optionally with :port, for example "
                     f"{KINDS['cisco_ios']['address_hint']}.")
    text = address.strip()
    if not text or "/" in text or " " in text:
        raise bad
    port = 22
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        if rest:
            if not rest.startswith(":") or not rest[1:].isdigit():
                raise bad
            port = int(rest[1:])
    elif text.count(":") == 1:
        host, _, p = text.partition(":")
        if not p.isdigit():
            raise bad
        port = int(p)
    else:
        host = text
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        if not _HOST.match(host):
            raise bad from None
    if not 1 <= port <= 65535:
        raise bad
    return host, port


def build(device: NetworkDevice, secret: str, transport=None, client_factory=None):
    """A collector for ``device``. ``transport`` (HTTP) and ``client_factory`` (SSH) are for tests."""
    from sutra_connectors import CiscoIosCollector, FortiGateCollector, PanOsCollector

    verify: bool | str = device.ca_bundle or True
    http = {"transport": transport} if transport is not None else {}
    if device.kind == "fortigate":
        return FortiGateCollector(device.address, secret, verify=verify, **http)
    if device.kind == "panos":
        return PanOsCollector(device.address, secret, verify=verify, **http)
    if device.kind == "cisco_ios":
        host, port = split_host(device.address)
        ssh = {"client_factory": client_factory} if client_factory is not None else {}
        return CiscoIosCollector(host, device.username, secret, port=port, host_key=device.host_key, **ssh)
    raise ValueError(f"Unknown device kind {device.kind!r}.")


def latest(db: Session, device_id: int) -> ConfigSnapshot | None:
    return db.scalars(select(ConfigSnapshot).where(ConfigSnapshot.device_id == device_id)
                      .order_by(ConfigSnapshot.id.desc())).first()


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat(timespec="seconds") if dt else None


def device_json(db: Session, d: NetworkDevice) -> dict:
    snap = latest(db, d.id)
    count = len(db.scalars(select(ConfigSnapshot.id).where(ConfigSnapshot.device_id == d.id)).all())
    return {"id": d.id, "kind": d.kind, "kind_label": KINDS[d.kind]["label"], "name": d.name, "address": d.address,
            "username": d.username, "has_secret": bool(d.secret), "ca_bundle": d.ca_bundle, "host_key": d.host_key,
            "site": d.site, "enabled": d.enabled, "last_attempt": _iso(d.last_attempt_at), "last_status": d.last_status,
            "last_error": d.last_error, "snapshots": count,
            "current": snapshot_json(snap) if snap else None}


def snapshot_json(s: ConfigSnapshot) -> dict:
    return {"id": s.id, "device": s.device_id, "collected": _iso(s.collected_at), "last_seen": _iso(s.last_seen_at),
            "hostname": s.hostname, "model": s.model, "serial": s.serial, "version": s.version,
            "format": s.config_format, "bytes": len(s.config.encode()), "masked": s.masked,
            "facts": dict(s.facts or {}), "arp": len(s.arp or []), "mac_table": len(s.mac_table or [])}


def diff(old: ConfigSnapshot | None, new: ConfigSnapshot) -> dict:
    """Unified diff from ``old`` to ``new`` (an empty "before" for the first snapshot), capped at DIFF_LINE_LIMIT."""
    before = old.config.splitlines() if old else []
    lines = list(difflib.unified_diff(before, new.config.splitlines(), lineterm="", n=3,
                                      fromfile=f"{_iso(old.collected_at)} UTC" if old else "(nothing before)",
                                      tofile=f"{_iso(new.collected_at)} UTC"))
    added = sum(1 for x in lines if x.startswith("+") and not x.startswith("+++"))
    removed = sum(1 for x in lines if x.startswith("-") and not x.startswith("---"))
    return {"from": old.id if old else None, "to": new.id, "added": added, "removed": removed,
            "truncated": len(lines) > DIFF_LINE_LIMIT, "lines": lines[:DIFF_LINE_LIMIT]}


class Collector:
    """Runs collections one at a time on a background thread, and on the daily scanner-pull schedule."""

    def __init__(self, app, transport=None, client_factory=None, factory: Callable | None = None):
        self.app = app
        self.transport, self.client_factory = transport, client_factory
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

    def start(self, trigger: str, user_id: int | None, device_id: int | None = None,
              background: bool = True) -> list[int]:
        """Collect from every enabled device, or from one. Raises RuntimeError if a collection is running."""
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("A configuration collection is already running.")
        try:
            with self.sessions() as db:
                q = select(NetworkDevice.id).order_by(NetworkDevice.id)
                q = q.where(NetworkDevice.id == device_id) if device_id else q.where(NetworkDevice.enabled.is_(True))
                ids = list(db.scalars(q))
            if not ids:
                raise ValueError("No such device." if device_id else "Add and switch on at least one device first.")
        except Exception:
            self._lock.release()
            raise
        if background:
            threading.Thread(target=self._run_locked, args=(ids, trigger, user_id), name="sutra-netconfig",
                             daemon=True).start()
        else:
            self._run_locked(ids, trigger, user_id)
        return ids

    def _run_locked(self, ids: list[int], trigger: str, user_id: int | None) -> None:
        try:
            self.run(ids, trigger, user_id)
        except Exception:
            log.exception("configuration collection crashed")
        finally:
            self._lock.release()

    def run(self, ids: list[int], trigger: str, user_id: int | None) -> list[dict]:
        results = []
        for device_id in ids:
            with self.sessions() as db:
                d = db.get(NetworkDevice, device_id)
                if d is None:
                    continue
                results.append(self._collect_one(db, d))
                db.commit()
        with self.sessions() as db:
            actor = None
            if user_id:
                from .models import User

                actor = db.get(User, user_id)
            audit(db, "data.config_collect", actor, "network_device", ",".join(str(i) for i in ids),
                  trigger=trigger, results=results)
            db.commit()
        return results

    def _collect_one(self, db: Session, d: NetworkDevice) -> dict:
        result = {"device": d.id, "name": d.name, "status": "failed", "error": ""}
        d.last_attempt_at = utcnow()
        try:
            secret = vault.open_(self.settings.secret_key, d.secret)
            collector = self.factory(d, secret, self.transport, self.client_factory)
            try:
                snap = collector.collect()
            finally:
                collector.close()
        except Exception as e:  # collectors raise errors without credentials in them
            d.last_status, d.last_error = "failed", f"{type(e).__name__}: {e}"[:1000]
            result["error"] = d.last_error
            log.warning("config collection from %s failed: %s", d.name, d.last_error)
            return result
        if snap.host_key and not d.host_key:
            d.host_key = snap.host_key
            audit(db, "data.device_host_key_pinned", None, "network_device", d.id, name=d.name,
                  host_key=snap.host_key)
        now = utcnow()
        prev = latest(db, d.id)
        arp = [{"ip": a.ip, "mac": a.mac, "interface": a.interface} for a in snap.arp]
        macs = [{"mac": m.mac, "vlan": m.vlan, "port": m.port} for m in snap.mac_table]
        fields = {"hostname": snap.hostname[:200], "model": snap.model[:120], "serial": snap.serial[:120],
                  "version": snap.version[:120], "facts": dict(snap.facts), "arp": arp, "mac_table": macs,
                  "masked": snap.masked}
        if prev is not None and prev.digest == snap.digest:
            for k, v in fields.items():
                setattr(prev, k, v)
            prev.last_seen_at = now
            status = "unchanged"
        else:
            db.add(ConfigSnapshot(device_id=d.id, collected_at=now, last_seen_at=now, digest=snap.digest,
                                  config_format=snap.config_format, config=snap.config, **fields))
            status = "first" if prev is None else "changed"
        d.last_status, d.last_error = status, ""
        result.update(status=status)
        return result

    # ---------- schedule ----------

    def due(self, db: Session, now: datetime) -> bool:
        """The daily pull schedule is on, today's hour (India time) has passed, and an enabled device has not been
        tried since then."""
        cfg = scanpull.schedule(db)
        if not cfg["enabled"]:
            return False
        local = now.replace(tzinfo=UTC).astimezone(drafting.IST)
        if local.hour < int(cfg["hour"]):
            return False
        slot = local.replace(hour=int(cfg["hour"]), minute=0, second=0, microsecond=0)
        slot_utc = slot.astimezone(UTC).replace(tzinfo=None)
        for last in db.scalars(select(NetworkDevice.last_attempt_at).where(NetworkDevice.enabled.is_(True))):
            if last is None or last < slot_utc:
                return True
        return False

    def tick(self, now: datetime | None = None) -> list[int] | None:
        with self.sessions() as db:
            if not self.due(db, now or utcnow()):
                return None
        try:
            return self.start("schedule", None, background=False)
        except (RuntimeError, ValueError):
            return None

    def start_schedule(self) -> None:
        threading.Thread(target=self._loop, name="sutra-netconfig-schedule", daemon=True).start()

    def _loop(self) -> None:
        while not self._stop.wait(scanpull.CHECK_SECONDS):
            try:
                self.tick()
            except Exception:
                log.exception("scheduled configuration collection failed")

    def stop(self) -> None:
        self._stop.set()
