"""Rule hit counts, which "unused rule" depends on. Configurations do not carry them: a device keeps counters that are
read separately, so the readers here take that separate output.

* ``from_csv``: ``rule,hits[,last_hit[,since]]`` (times ISO 8601 or Unix seconds). Works for any vendor.
* ``from_panos_xml``: the reply of ``show rule-hit-count vsys vsys-name vsys1 rule-base security rules all``
  (element names as remembered from PAN-OS 9/10 output; not checked against a vendor page).
* ``from_ios_access_lists``: ``show access-lists`` text, ``(N matches)`` after each entry. IOS keeps no last-hit time.
* ``from_fortios_json``: the reply of ``GET /api/v2/monitor/firewall/policy`` (``policyid``, ``hit_count``,
  ``last_used``, ``first_used``; field names as remembered, not checked against a vendor page).

Keys match :attr:`sutra.attack.model.Rule.key`: FortiOS policy id, PAN-OS rule name, IOS ``<ACL> <sequence>``.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from defusedxml import ElementTree as ET


@dataclass
class RuleHits:
    hits: int
    last_hit: datetime | None = None
    since: datetime | None = None  # when counting began (counters reset on reboot or by an admin), if known


HitMap = dict[str, RuleHits]


def _when(value: object) -> datetime | None:
    if value in (None, "", 0, "0", "never", "-"):
        return None
    text = str(value).strip()
    try:
        if text.replace(".", "", 1).isdigit():
            return datetime.fromtimestamp(float(text), UTC).replace(tzinfo=None)
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return dt.astimezone(UTC).replace(tzinfo=None) if dt.tzinfo else dt
    except (ValueError, OverflowError, OSError):
        return None


def from_csv(text: str) -> HitMap:
    out: HitMap = {}
    for row in csv.DictReader(io.StringIO(text)):
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        key = row.get("rule") or row.get("key")
        if not key or not row.get("hits", "").isdigit():
            raise ValueError("Each row needs a rule and a numeric hits column (rule,hits,last_hit,since).")
        out[key] = RuleHits(int(row["hits"]), _when(row.get("last_hit")), _when(row.get("since")))
    if not out:
        raise ValueError("No rows found.")
    return out


def from_panos_xml(text: str) -> HitMap:
    root = ET.fromstring(text.encode())
    out: HitMap = {}
    for e in root.iter("entry"):
        hc = e.find("hit-count")
        if hc is None or not (hc.text or "").strip().isdigit():
            continue
        started = [_when((e.findtext(t) or "").strip()) for t in ("last-reset-timestamp", "rule-creation-timestamp")]
        out[e.get("name", "")] = RuleHits(int(hc.text.strip()), _when(e.findtext("last-hit-timestamp")),
                                          max((s for s in started if s), default=None))
    if not out:
        raise ValueError("No rule hit counts found in this XML.")
    return out


_IOS = re.compile(r"^\s*(\d+)\s+(permit|deny)\b.*?(?:\((\d+) match(?:es)?\))?\s*$")


def from_ios_access_lists(text: str, since: datetime | None = None) -> HitMap:
    out: HitMap = {}
    acl = ""
    for line in text.splitlines():
        m = re.match(r"^(?:Standard|Extended)\s+IP access list\s+(\S+)", line)
        if m:
            acl = m.group(1)
            continue
        e = _IOS.match(line)
        if acl and e:
            out[f"{acl} {e.group(1)}"] = RuleHits(int(e.group(3) or 0), None, since)
    if not out:
        raise ValueError("No access-list entries found in this output.")
    return out


def from_fortios_json(text: str) -> HitMap:
    data = json.loads(text)
    rows = data.get("results", data) if isinstance(data, dict) else data
    out: HitMap = {}
    for r in rows:
        if "policyid" in r:
            out[str(r["policyid"])] = RuleHits(int(r.get("hit_count", 0) or 0), _when(r.get("last_used")),
                                               _when(r.get("first_used")))
    if not out:
        raise ValueError("No policy hit counts found in this JSON.")
    return out


def parse(fmt: str, text: str, since: datetime | None = None) -> HitMap:
    if fmt == "csv":
        return from_csv(text)
    if fmt == "panos_xml":
        return from_panos_xml(text)
    if fmt == "ios_access_lists":
        return from_ios_access_lists(text, since)
    if fmt == "fortios_json":
        return from_fortios_json(text)
    raise ValueError(f"Unknown hit count format {fmt!r}.")


FORMATS = {"csv": "CSV: rule,hits,last_hit,since", "panos_xml": "PAN-OS: show rule-hit-count (XML)",
           "ios_access_lists": "Cisco IOS: show access-lists",
           "fortios_json": "FortiOS: monitor/firewall/policy (JSON)"}
