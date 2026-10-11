"""Live threat intelligence: the CISA Known Exploited Vulnerabilities catalog and FIRST EPSS scores.

- **KEV** (``SUTRA_KEV_URL``, by default CISA's JSON feed) decides SSVC "active exploitation": a CVE is actively
  exploited when CISA lists it, with the date it was added and whether it is known to be used in ransomware.
- **EPSS** (``SUTRA_EPSS_URL``, by default FIRST's API) gives each CVE in the current import the probability of
  exploitation activity in the next 30 days and its percentile, for display and sorting. It does not change SSVC.
- **Public exploit code ("poc")** has no free authoritative feed. Sutra keeps the short curated list that ships in
  ``sutra/data/threat_intel.json`` for this, labelled as such on every screen.

Until a feed has been fetched, the shipped file is used as is and every screen says it is a sample. Feeds refresh once
a day and on demand; a failed fetch keeps the last good copy and is shown on the Import data page. After a refresh
the current import is analysed again so SSVC reflects the new catalog.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from .. import risk

log = logging.getLogger("sutra.intel")
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
EPSS_BATCH = 100  # the API's default page size; one request per batch of CVEs
REFRESH_EVERY = timedelta(hours=24)
CHECK_SECONDS = 3600
TIMEOUT = httpx.Timeout(60.0)


def _now() -> str:
    return datetime.now(UTC).replace(tzinfo=None).isoformat(timespec="seconds")


class IntelStore:
    """Feeds kept under ``<workspace>/intel``: ``kev.json`` (the catalog as fetched), ``epss.json`` (scores by CVE) and
    ``status.json`` (when each was fetched, and the last error)."""

    def __init__(self, workspace: Path, kev_url: str | None = None, epss_url: str | None = None, transport=None):
        self.dir = Path(workspace) / "intel"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.kev_url = kev_url or os.environ.get("SUTRA_KEV_URL", KEV_URL)
        self.epss_url = epss_url or os.environ.get("SUTRA_EPSS_URL", EPSS_URL)
        self.transport = transport

    # ---------- files ----------

    def _read(self, name: str, default):
        p = self.dir / name
        try:
            return json.loads(p.read_text(encoding="utf-8")) if p.exists() else default
        except (OSError, ValueError):
            log.warning("unreadable %s; ignoring it", p)
            return default

    def _write(self, name: str, value) -> None:
        tmp = self.dir / f".{name}.tmp"
        tmp.write_text(json.dumps(value), encoding="utf-8")
        tmp.replace(self.dir / name)

    def status(self) -> dict:
        s = self._read("status.json", {})
        return {"kev": s.get("kev", {}), "epss": s.get("epss", {}), "kev_url": self.kev_url,
                "epss_url": self.epss_url, "live": bool(s.get("kev", {}).get("fetched_at"))}

    def _set_status(self, feed: str, **values) -> None:
        s = self._read("status.json", {})
        s[feed] = {**s.get(feed, {}), **values}
        self._write("status.json", s)

    # ---------- fetching ----------

    def _client(self) -> httpx.Client:
        return httpx.Client(timeout=TIMEOUT, transport=self.transport, follow_redirects=True,
                            headers={"User-Agent": "Sutra threat-intel refresh"})

    def fetch_kev(self) -> int:
        with self._client() as c:
            r = c.get(self.kev_url)
            r.raise_for_status()
            data = r.json()
        vulns = data.get("vulnerabilities")
        if not isinstance(vulns, list) or not vulns:
            raise ValueError("the KEV feed has no vulnerabilities list")
        keep = []
        for v in vulns:
            cve = str(v.get("cveID", "")).strip().upper()
            if CVE.match(cve):
                keep.append({"cveID": cve, "vulnerabilityName": str(v.get("vulnerabilityName", "")).strip(),
                             "vendorProject": v.get("vendorProject", ""), "product": v.get("product", ""),
                             "dateAdded": v.get("dateAdded", ""), "dueDate": v.get("dueDate", ""),
                             "knownRansomwareCampaignUse": v.get("knownRansomwareCampaignUse", "")})
        if len(keep) < len(vulns) * 0.9:
            raise ValueError("the KEV feed's entries do not look like CVE records")
        self._write("kev.json", {"catalogVersion": data.get("catalogVersion", ""),
                                 "dateReleased": data.get("dateReleased", ""), "vulnerabilities": keep})
        self._set_status("kev", fetched_at=_now(), catalog_version=data.get("catalogVersion", ""), count=len(keep),
                         error="")
        return len(keep)

    def fetch_epss(self, cves: set[str]) -> int:
        """Scores for these CVEs (the ones in the current import), merged into the stored scores."""
        wanted = sorted(c for c in cves if CVE.match(c))
        scores = self._read("epss.json", {})
        got = 0
        with self._client() as c:
            for i in range(0, len(wanted), EPSS_BATCH):
                batch = wanted[i:i + EPSS_BATCH]
                r = c.get(self.epss_url, params={"cve": ",".join(batch), "limit": EPSS_BATCH})
                r.raise_for_status()
                for row in r.json().get("data", []):
                    cve = str(row.get("cve", "")).upper()
                    if cve in batch:
                        scores[cve] = {"epss": float(row["epss"]), "percentile": float(row["percentile"]),
                                       "date": row.get("date", "")}
                        got += 1
        self._write("epss.json", scores)
        self._set_status("epss", fetched_at=_now(), count=len(scores), asked=len(wanted), error="")
        return got

    def refresh(self, cves: set[str]) -> dict:
        """Fetch both feeds. A failure is recorded and the last good copy kept."""
        out = {}
        for feed, fn in (("kev", self.fetch_kev), ("epss", lambda: self.fetch_epss(cves))):
            try:
                out[feed] = {"ok": True, "count": fn()}
            except Exception as e:  # network, HTTP status, malformed feed
                msg = f"{type(e).__name__}: {e}"[:500]
                log.warning("%s refresh failed: %s", feed, msg)
                self._set_status(feed, error=msg, failed_at=_now())
                out[feed] = {"ok": False, "error": msg}
        return out

    def due(self) -> bool:
        kev = self.status()["kev"]
        last = max(filter(None, (kev.get("fetched_at"), kev.get("failed_at"))), default=None)
        return not last or datetime.fromisoformat(last) < datetime.now(UTC).replace(tzinfo=None) - REFRESH_EVERY

    # ---------- the intel the analysis uses ----------

    def build(self) -> dict:
        """CVE -> {"exploitation", "name", "source", ...}. KEV decides "active"; the curated list gives "poc"."""
        shipped = risk.load_intel()
        kev = self._read("kev.json", None)
        intel: dict[str, dict] = {}
        if kev is None:  # no live catalog yet: the shipped sample, labelled
            for cve, v in shipped.items():
                intel[cve] = {**v, "source": "sample"}
        else:
            for cve, v in shipped.items():
                if v.get("exploitation") == "poc":
                    intel[cve] = {**v, "source": "curated"}
            for v in kev["vulnerabilities"]:
                intel[v["cveID"]] = {"exploitation": "active", "name": v["vulnerabilityName"], "source": "CISA KEV",
                                     "kev_added": v["dateAdded"],
                                     "ransomware": v["knownRansomwareCampaignUse"] == "Known"}
        for cve, s in self._read("epss.json", {}).items():
            entry = intel.setdefault(cve, {"exploitation": "none"})
            entry.update(epss=s["epss"], epss_percentile=s["percentile"], epss_date=s["date"])
        return intel


class IntelUpdater:
    """Refreshes the feeds once a day, then re-analyses the current import."""

    def __init__(self, app):
        self.app = app
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def busy(self) -> bool:
        return self._lock.locked()

    def refresh(self) -> dict:
        """Fetch the feeds and re-analyse. Raises RuntimeError if a refresh is already running."""
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("Threat intel is already being refreshed.")
        try:
            store: IntelStore = self.app.state.intel
            res = self.app.state.analysis.result
            cves = {c for f in res.findings for c in f.cves} if res else set()
            out = store.refresh(cves)
            self.app.state.analysis.set_intel(store.build())
            with self.app.state.sessionmaker() as db:
                self.app.state.analysis.load_current(db)
            return out
        finally:
            self._lock.release()

    def start(self) -> None:
        threading.Thread(target=self._loop, name="sutra-intel", daemon=True).start()

    def _loop(self) -> None:
        while True:
            try:
                if self.app.state.intel.due():
                    self.refresh()
            except RuntimeError:
                pass  # a refresh started by hand is running
            except Exception:
                log.exception("threat intel refresh failed")
            if self._stop.wait(CHECK_SECONDS):
                return

    def stop(self) -> None:
        self._stop.set()
