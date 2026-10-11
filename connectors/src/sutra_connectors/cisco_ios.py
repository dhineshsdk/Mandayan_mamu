"""Cisco IOS and IOS-XE collector (switches and routers): the running configuration, the software version, the ARP
table and the MAC address table, over SSH.

Source (checked 2026-10-11; notes in ``docs/api-notes/network-devices.md``): the commands and the session set-up are
the ones Netmiko 4.8.0 (PyPI, ``netmiko/cisco/cisco_ios.py``) sends to ``cisco_ios`` devices (``terminal width 511``,
``terminal length 0``). The output formats are from Network to Code's ``ntc-templates`` 9.3.0 (PyPI, the
``cisco_ios_show_*`` TextFSM templates) and the raw device outputs in its test suite, which the tests here use.

Read-only: :class:`~sutra_connectors.ssh.CliSession` sends only the six commands in :data:`COMMANDS`, none of which
enters configuration mode or changes anything that survives the session. Reading the running configuration needs
privileged EXEC: the account must log in at the ``#`` prompt (privilege level 15, or a privilege level or parser view
that allows ``show running-config``). Sutra never sends ``enable``.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime, timezone

import paramiko

from .errors import ApiError, ConfigurationError
from .netdevices import FORMAT_IOS, ArpEntry, DeviceSnapshot, MacEntry, mask_ios, norm_mac
from .ssh import CliSession

COMMANDS = ("terminal width 511", "terminal length 0", "show version", "show running-config", "show ip arp",
            "show mac address-table")

_ARP = re.compile(r"^Internet\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)\s+(\S+)\s+\S+(?:\s+(\S+))?")
_DOTTED_MAC = re.compile(r"\b[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\b")
_VERSION = re.compile(r"\bVersion\s+([^\s,]+)")
_MODEL = (re.compile(r"^[Mm]odel [Nn]umber\s*:\s*(\S+)", re.M), re.compile(r"^cisco\s+(\S+)\s.*processor", re.M))
_SERIAL = (re.compile(r"^System [Ss]erial [Nn]umber\s*:\s*(\S+)", re.M),
           re.compile(r"^Processor board ID\s+(\S+)", re.M))
_HOSTNAME = re.compile(r"^hostname\s+(\S+)", re.M)


def _rejected(output: str) -> bool:
    """IOS answers a command it does not have, or one the account may not run, with a line starting with %."""
    first = output.strip().split("\n", 1)[0].strip()
    return first.startswith("%") or first.lower().startswith("command authorization failed")


def parse_version(text: str) -> tuple[str, str, str]:
    """(software version, model, serial) from ``show version``."""
    version = ""
    for line in text.splitlines():
        if "Cisco IOS" in line or "IOS-XE" in line or "IOS XE" in line:
            m = _VERSION.search(line)
            if m:
                version = m.group(1)
                break
    model = next((m.group(1) for p in _MODEL if (m := p.search(text))), "")
    serial = next((m.group(1) for p in _SERIAL if (m := p.search(text))), "")
    return version, model, serial


def parse_arp(text: str) -> tuple[ArpEntry, ...]:
    """Learned entries of ``show ip arp``. Age ``-`` marks the device's own interface addresses, which are left out,
    as are incomplete entries."""
    out = []
    for line in text.splitlines():
        m = _ARP.match(line.strip())
        if not m or m.group(2) == "-":
            continue
        mac = norm_mac(m.group(3))
        if mac:
            out.append(ArpEntry(ip=m.group(1), mac=mac, interface=m.group(4) or ""))
    return tuple(out)


def parse_mac_table(text: str) -> tuple[MacEntry, ...]:
    """Dynamically learned entries of ``show mac address-table``, in any of the layouts IOS uses."""
    out = []
    for line in text.splitlines():
        m = _DOTTED_MAC.search(line)
        if not m:
            continue
        tokens = [t for t in line.split() if t != "*"]
        if not any(t.lower() == "dynamic" for t in tokens):
            continue  # static, secure and CPU entries are the switch's own, not devices on the network
        numbers = [t for t in tokens if t.isdigit()]
        out.append(MacEntry(mac=norm_mac(m.group(0)), vlan=numbers[0] if numbers else "", port=tokens[-1]))
    return tuple(out)


class CiscoIosCollector:
    """Read a Cisco IOS or IOS-XE device over SSH with a user name and password."""

    vendor = "Cisco IOS"

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        port: int = 22,
        host_key: str = "",
        timeout: float = 30.0,
        command_timeout: float = 300.0,
        client_factory: Callable[[], paramiko.SSHClient] = paramiko.SSHClient,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        self.session = CliSession("Cisco IOS", host, username, password, allow=COMMANDS, port=port,
                                  host_key=host_key, timeout=timeout, command_timeout=command_timeout,
                                  client_factory=client_factory)
        self._clock = clock
        self.source = f"cisco-ios-ssh:{host}"

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> CiscoIosCollector:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def collect(self) -> DeviceSnapshot:
        s = self.session
        prompt = s.open()
        if prompt.endswith(">"):
            raise ConfigurationError(
                "Cisco IOS: the account logs in at user EXEC (>), which cannot read the running configuration. "
                "Give it privilege level 15 or a parser view that allows show running-config; Sutra does not send "
                "enable.")
        s.run("terminal width 511")
        s.run("terminal length 0")
        version_text = s.run("show version")
        running = s.run("show running-config")
        if _rejected(running) or not re.search(r"^end\s*$", running, re.M):
            raise ApiError("Cisco IOS: show running-config did not return a configuration: "
                           + running.strip()[:200])
        arp_text = s.run("show ip arp")
        mac_text = s.run("show mac address-table")
        config, masked = mask_ios(running)
        version, model, serial = parse_version(version_text)
        m = _HOSTNAME.search(config)
        return DeviceSnapshot(
            vendor=self.vendor,
            source=self.source,
            collected_at=self._clock(),
            hostname=m.group(1) if m else prompt.rstrip("#>"),
            model=model,
            serial=serial,
            version=version,
            config=config,
            config_format=FORMAT_IOS,
            masked=masked,
            arp=() if _rejected(arp_text) else parse_arp(arp_text),
            mac_table=() if _rejected(mac_text) else parse_mac_table(mac_text),
            host_key=s.host_key,
        )
