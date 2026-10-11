"""Palo Alto Networks firewall collector: the running configuration and the software version, through the PAN-OS
XML API.

Source (checked 2026-10-11; notes in ``docs/api-notes/network-devices.md``): Palo Alto Networks' ``pan-python``
0.26.0 (PyPI, ``pan/xapi.py``), which sends every request to ``/api/`` as a form-encoded POST with the API key in
the ``key`` field; ``type=config&action=show`` returns the active (running) configuration at ``xpath`` (``show`` is
"show active config", ``get`` the candidate); ``type=op`` runs an operational command given as XML; a response is
``<response status="success|error">``. ``pan-os-python`` 1.13.1 (PyPI) runs ``show system info`` and reads
``system/sw-version``, ``system/model`` and ``system/serial`` from its result.

Read-only: every request is a POST to ``/api/`` (the XML API takes reads as POSTs too), and the allowlist pins the
request type, the action and the one operational command, so no other operation can be sent. The API key should
belong to an administrator with a read-only role.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime, timezone
from urllib.parse import urlsplit
from xml.etree.ElementTree import Element, indent, tostring  # noqa: S405 (serialises trees parsed by defusedxml)

import httpx
from defusedxml import ElementTree as SafeET

from .errors import ApiError, AuthenticationError, ConfigurationError
from .http import Allow, HttpSession, RetryPolicy, require_https
from .netdevices import FORMAT_PANOS, DeviceSnapshot, mask_panos

API_PATH = "/api/"
SYSTEM_INFO = "<show><system><info></info></system></show>"
ALLOW = (
    Allow("POST", API_PATH, require=(("type", "op"), ("cmd", SYSTEM_INFO))),
    Allow("POST", API_PATH, require=(("type", "config"), ("action", "show"), ("xpath", "/config"))),
)


class PanOsCollector:
    """Read a PAN-OS firewall's running configuration with an XML API key."""

    vendor = "Palo Alto Networks PAN-OS"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = 120.0,
        verify: bool | str = True,
        retry: RetryPolicy | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        if not base_url:
            raise ConfigurationError("PAN-OS: the management address is required")
        if not api_key:
            raise ConfigurationError("PAN-OS: an API key is required")
        base_url = require_https(base_url, "base_url")
        self._key, self._clock = api_key, clock
        self.http = HttpSession(name="PAN-OS", base_url=base_url, headers={"Accept": "application/xml"},
                                allow=ALLOW, timeout=timeout, verify=verify, retry=retry, transport=transport,
                                sleep=sleep)
        self.source = f"panos-api:{urlsplit(base_url).hostname}"

    def close(self) -> None:
        self.http.close()

    def __enter__(self) -> PanOsCollector:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _call(self, what: str, **fields: str) -> Element:
        """POST one request; the ``<result>`` element of a successful response."""
        resp = self.http.request("POST", API_PATH, data={**fields, "key": self._key})
        try:
            root = SafeET.fromstring(resp.content)
        except SafeET.ParseError as exc:
            raise ApiError(f"PAN-OS: the {what} response is not XML", status=resp.status_code) from exc
        if root.tag != "response":
            raise ApiError(f"PAN-OS: unexpected {what} response", status=resp.status_code)
        if root.get("status") != "success":
            msg = " ".join(t.strip() for t in root.itertext() if t.strip())[:300]
            if root.get("code") == "403":  # DOC GAP: code 403 read as a refused key or role, as remembered
                raise AuthenticationError(f"PAN-OS: {what} was refused: {msg}")
            raise ApiError(f"PAN-OS: {what} failed: {msg}", status=resp.status_code, code=root.get("code"))
        result = root.find("result")
        if result is None:
            raise ApiError(f"PAN-OS: the {what} response has no result", status=resp.status_code)
        return result

    def collect(self) -> DeviceSnapshot:
        info = self._call("show system info", type="op", cmd=SYSTEM_INFO).find("system")
        if info is None:
            raise ApiError("PAN-OS: show system info returned no system element")
        config = self._call("show running configuration", type="config", action="show", xpath="/config").find(
            "config")
        if config is None:
            raise ApiError("PAN-OS: the running configuration response has no config element")
        masked = mask_panos(config)
        # One element per line, two-space indent, whatever layout the firewall sent, so that changes diff cleanly.
        for el in config.iter():
            if el.text is not None and not el.text.strip():
                el.text = None
            el.tail = None
        indent(config, "  ")
        hostname = (info.findtext("hostname") or "").strip() or (
            config.findtext("devices/entry/deviceconfig/system/hostname") or "").strip()
        rules = config.findall(".//rulebase/security/rules/entry")
        return DeviceSnapshot(
            vendor=self.vendor,
            source=self.source,
            collected_at=self._clock(),
            hostname=hostname,
            model=(info.findtext("model") or "").strip(),
            serial=(info.findtext("serial") or "").strip(),
            version=(info.findtext("sw-version") or "").strip(),
            config=tostring(config, encoding="unicode") + "\n",
            config_format=FORMAT_PANOS,
            masked=masked,
            facts={"security_rules": len(rules)},
        )
