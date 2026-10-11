"""FortiGate collector: the full configuration and the software version, through the FortiOS REST API.

Source (checked 2026-10-11; notes in ``docs/api-notes/network-devices.md``): Fortinet's own Ansible collection
(``fortinet-ansible-dev/ansible-galaxy-fortios-collection``: ``plugins/modules/fortios_monitor_fact.py`` lists the
monitor endpoints ``system/config/backup`` with parameters ``scope`` (required), ``destination``, ``vdom``,
``password_mask`` and ``file_format``, and ``system/status``; ``plugins/httpapi/fortios.py`` sends an API token as
``Authorization: Bearer``; ``plugins/module_utils/fortios/fortios.py`` reads them with GET under ``/api/v2/monitor/``)
and Fortinet's ``fortiosapi`` 1.0.5 (PyPI), whose test downloads ``system/config/backup`` with
``destination=file&scope=global`` and which reads the FortiOS version from the ``version`` field of the JSON envelope.

Read-only: two GET endpoints. The API token should belong to a REST API administrator with a read-only profile.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from .errors import ApiError, ConfigurationError
from .http import Allow, HttpSession, RetryPolicy, require_https
from .netdevices import FORMAT_FORTIOS, DeviceSnapshot, count_fortios_policies, mask_fortios

STATUS_PATH = "/api/v2/monitor/system/status"
BACKUP_PATH = "/api/v2/monitor/system/config/backup"
ALLOW = (Allow("GET", STATUS_PATH), Allow("GET", BACKUP_PATH, require=(("scope", "global"),)))
_HOSTNAME = re.compile(r'^\s*set hostname\s+"?([^"\s]+)"?\s*$')


def _hostname(config: str) -> str:
    """``set hostname`` inside ``config system global``."""
    in_global = False
    for line in config.splitlines():
        s = line.strip()
        if s == "config system global":
            in_global = True
        elif in_global and s == "end":
            in_global = False
        elif in_global:
            m = _HOSTNAME.match(line)
            if m:
                return m.group(1)
    return ""


class FortiGateCollector:
    """Read a FortiGate's configuration (every VDOM) with a REST API token."""

    vendor = "Fortinet FortiGate"

    def __init__(
        self,
        base_url: str,
        api_token: str,
        *,
        timeout: float = 120.0,
        verify: bool | str = True,
        retry: RetryPolicy | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        if not base_url:
            raise ConfigurationError("FortiGate: the management address is required")
        if not api_token:
            raise ConfigurationError("FortiGate: an API token is required")
        base_url = require_https(base_url, "base_url")
        self._clock = clock
        self.http = HttpSession(name="FortiGate", base_url=base_url,
                                headers={"Authorization": f"Bearer {api_token}"}, allow=ALLOW, timeout=timeout,
                                verify=verify, retry=retry, transport=transport, sleep=sleep)
        self.source = f"fortigate-api:{urlsplit(base_url).hostname}"

    def close(self) -> None:
        self.http.close()

    def __enter__(self) -> FortiGateCollector:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def collect(self) -> DeviceSnapshot:
        status = self._json(self.http.request("GET", STATUS_PATH), "system status")
        results = status.get("results") if isinstance(status.get("results"), dict) else {}
        resp = self.http.request("GET", BACKUP_PATH, params={"scope": "global", "destination": "file",
                                                             "password_mask": "true"})
        text = resp.text
        if text.lstrip().startswith("{"):  # an error comes back as JSON instead of the file
            body = self._json(resp, "configuration backup")
            raise ApiError(f"FortiGate: the configuration backup was refused: {body.get('status', '')} "
                           f"{body.get('error', '')}".strip(), status=resp.status_code)
        if "config system global" not in text:
            raise ApiError("FortiGate: the configuration backup is not a FortiOS configuration file",
                           status=resp.status_code)
        config, masked = mask_fortios(text)
        return DeviceSnapshot(
            vendor=self.vendor,
            source=self.source,
            collected_at=self._clock(),
            hostname=_hostname(config) or str(results.get("hostname") or ""),
            # DOC GAP: model_name and model_number are field names as remembered from FortiOS's system/status.
            model=" ".join(str(results.get(k) or "") for k in ("model_name", "model_number")).strip(),
            serial=str(status.get("serial") or ""),
            version=str(status.get("version") or ""),
            config=config,
            config_format=FORMAT_FORTIOS,
            masked=masked,
            facts={"firewall_policies": count_fortios_policies(config)},
        )

    @staticmethod
    def _json(resp: httpx.Response, what: str) -> dict:
        try:
            body = resp.json()
        except ValueError as exc:
            raise ApiError(f"FortiGate: the {what} response is not JSON", status=resp.status_code) from exc
        if not isinstance(body, dict):
            raise ApiError(f"FortiGate: unexpected {what} response", status=resp.status_code)
        return body
