"""Read-only configuration collection from firewalls and switches: the record every collector returns, and the
secret masking every configuration goes through before it leaves the collector.

Collectors: :class:`~sutra_connectors.fortigate.FortiGateCollector` (FortiOS REST API),
:class:`~sutra_connectors.panos.PanOsCollector` (PAN-OS XML API) and
:class:`~sutra_connectors.cisco_ios.CiscoIosCollector` (Cisco IOS and IOS-XE over SSH). Each has one method,
``collect()``, that returns a :class:`DeviceSnapshot`.

Secrets are masked here, in the collector, so a stored configuration never holds a password, key, pre-shared key or
SNMP community, even an encrypted or hashed one (type 7 and FortiOS ``ENC`` values can be reversed, and hashes can be
cracked). Masking keeps the setting's name so a reviewer still sees that a password is set and when it changed.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from xml.etree.ElementTree import Element  # noqa: S405 (only builds and walks trees parsed by defusedxml)

MASK = "SUTRA-MASKED"  # no characters that need escaping in XML or quoting in a CLI

FORMAT_FORTIOS = "fortios"
FORMAT_PANOS = "panos-xml"
FORMAT_IOS = "ios"


@dataclass(frozen=True)
class ArpEntry:
    """An IP address the device has seen on a directly connected network, with the MAC address that answered."""

    ip: str
    mac: str  # lower case, colon separated
    interface: str


@dataclass(frozen=True)
class MacEntry:
    """A MAC address a switch has learned on a port."""

    mac: str  # lower case, colon separated
    vlan: str
    port: str


@dataclass(frozen=True)
class DeviceSnapshot:
    """What one collection read from one device. ``config`` is already masked (see the module docstring)."""

    vendor: str  # "Fortinet FortiGate", "Palo Alto Networks PAN-OS", "Cisco IOS"
    source: str  # where it was read, e.g. "fortigate-api:fw1.plant.example.in"
    collected_at: datetime
    hostname: str
    model: str
    serial: str
    version: str  # software version as the device reports it
    config: str
    config_format: str  # FORMAT_*
    masked: int  # how many secret values were masked
    facts: dict[str, int] = field(default_factory=dict)  # e.g. {"firewall_rules": 42}
    arp: tuple[ArpEntry, ...] = ()
    mac_table: tuple[MacEntry, ...] = ()
    host_key: str = ""  # SSH host key fingerprint seen, for collectors that use SSH

    @property
    def digest(self) -> str:
        """SHA-256 of the configuration without the lines a device rewrites when nothing changed."""
        return config_digest(self.config, self.config_format)


# ---------- change detection ----------

# Lines that change without a configuration change: IOS rewrites the change and save stamps and the NTP clock
# period, and the IOS byte count follows them; FortiOS backups start with comment lines (``#config-version=...``,
# ``#conf_file_ver=...``) that change on every save.
_VOLATILE = {
    FORMAT_IOS: re.compile(r"^(?:! Last configuration change at |! NVRAM config last updated at |"
                           r"! No configuration change since last restart|ntp clock-period |Building configuration|"
                           r"Current configuration : )"),
    FORMAT_FORTIOS: re.compile(r"^#"),
}


def config_digest(config: str, config_format: str) -> str:
    volatile = _VOLATILE.get(config_format)
    lines = [ln.rstrip() for ln in config.splitlines()]
    if volatile is not None:
        lines = [ln for ln in lines if not volatile.match(ln)]
    return hashlib.sha256("\n".join(lines).strip().encode()).hexdigest()


# ---------- MAC addresses ----------

_HEX = re.compile(r"[0-9a-f]")


def norm_mac(text: str) -> str:
    """``0000.0c59.f892``, ``00-00-0C-59-F8-92`` or ``00:00:0c:59:f8:92`` as ``00:00:0c:59:f8:92``; else ""."""
    digits = "".join(_HEX.findall(text.lower()))
    if len(digits) != 12 or len(re.sub(r"[0-9a-fA-F.:\-]", "", text)) != 0:
        return ""
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


# ---------- masking: Cisco IOS ----------

# Each pattern's last group is the secret. ``\d\s+`` before it is the IOS encryption type (0, 5, 6, 7, 8 or 9),
# which is kept: it tells a reviewer whether the value was stored in clear text.
_IOS_SECRETS = (
    # enable secret 9 ..., username x privilege 15 secret 9 ..., password 7 ... (line vty), neighbor x password ...
    re.compile(r"(\b(?:secret|password)\s+(?:\d{1,2}\s+)?)(?!encryption\b)(\S+)"),
    re.compile(r"^(\s*snmp-server community\s+)(\S+)"),
    re.compile(r"^(\s*key-string\s+(?:\d\s+)?)(\S+)"),
    re.compile(r"(\bmessage-digest-key\s+\d+\s+md5\s+(?:\d\s+)?)(\S+)"),
    re.compile(r"^(\s*ntp authentication-key\s+\d+\s+md5\s+)(\S+)"),
    re.compile(r"^(?!\s*ntp\b)(.*\bauthentication-key\s+(?:\d\s+)?)(\S+)"),
    re.compile(r"^(\s*(?:tacacs-server|radius-server)\b.*?\bkey\s+(?:\d\s+)?)(\S+)"),
    re.compile(r"^(\s*crypto isakmp key\s+(?:\d\s+)?)(\S+)"),
    re.compile(r"(\bpre-shared-key\s+(?:local\s+|remote\s+)?(?:\d\s+)?)(\S+)"),
    re.compile(r"(\bwpa-psk\s+(?:ascii|hex)\s+(?:\d\s+)?)(\S+)"),
    # "key 7 <value>" or "key <value>" inside a tacacs server or radius server block. A lone number is a key chain's
    # key ID, not a secret.
    re.compile(r"^(\s+key\s+\d\s+)(\S+)"),
    re.compile(r"^(\s+key\s+)(?!\d+\s*$)(\S+)\s*$"),
)


def mask_ios(config: str) -> tuple[str, int]:
    out, count = [], 0

    def mask(m: re.Match) -> str:
        nonlocal count
        if m.group(2) == MASK:
            return m.group(0)
        count += 1
        return m.group(1) + MASK

    for line in config.splitlines():
        for pattern in _IOS_SECRETS:
            line = pattern.sub(mask, line)
        out.append(line)
    return "\n".join(out) + ("\n" if config.endswith("\n") else ""), count


# ---------- masking: FortiOS ----------

# ``set <name> <value>`` where the name is a secret. FortiOS names them password, passwd, psksecret, secret,
# private-key, passphrase, auth-pwd and so on.
_FORTI_NAME = re.compile(r"(?:^|-)(?:password|passwd|passphrase|secret|psksecret|pwd|psk|key|private-key)\d*$")
_FORTI_SET = re.compile(r"^(\s*set\s+)(\S+)(\s+)(.*)$")
_FORTI_ENC = re.compile(r"\bENC\s+(?!SUTRA-MASKED)\S+")


def _quote_open(value: str) -> bool:
    """True when ``value`` opens a double-quoted string it does not close (a multi-line certificate or key)."""
    return value.startswith('"') and len(re.findall(r'(?<!\\)"', value)) % 2 == 1


def mask_fortios(config: str) -> tuple[str, int]:
    out, count = [], 0
    lines = config.splitlines()
    i = 0
    stack: list[str] = []  # open "config ..." sections
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith("config "):
            stack.append(stripped[7:])
        elif stripped == "end" and stack:
            stack.pop()
        m = _FORTI_SET.match(line)
        secret_name = m is not None and (_FORTI_NAME.search(m.group(2)) is not None or (
            # an SNMP v1/v2c community's name is the community string
            m.group(2) == "name" and bool(stack) and stack[-1] == "system snmp community"))
        if m and secret_name and not m.group(4).startswith(("ENC " + MASK, MASK)):
            value = m.group(4)
            prefix = m.group(1) + m.group(2) + m.group(3)
            out.append(prefix + ("ENC " + MASK if value.startswith("ENC ") else MASK))
            count += 1
            if _quote_open(value):  # skip the rest of a multi-line quoted value
                i += 1
                while i < len(lines) and not lines[i].rstrip().endswith('"'):
                    i += 1
            i += 1
            continue
        line, n = _FORTI_ENC.subn("ENC " + MASK, line)
        count += n
        out.append(line)
        i += 1
    return "\n".join(out) + ("\n" if config.endswith("\n") else ""), count


# ---------- masking: PAN-OS ----------

_PANOS_TAGS = frozenset({"phash", "password", "passwd", "secret", "key", "private-key", "community", "authpwd",
                         "privpwd", "auth-password", "priv-password", "bind-password", "shared-secret", "api-key",
                         "passphrase"})
_PANOS_SUFFIXES = ("-password", "-secret", "-key", "-passphrase")


def mask_panos(root: Element) -> int:
    """Mask, in place, the text of every leaf element that holds a secret. Returns how many were masked."""
    count = 0
    for el in root.iter():
        tag = el.tag if isinstance(el.tag, str) else ""
        if len(el) or not (el.text or "").strip():
            continue  # containers such as <pre-shared-key><key>...</key></pre-shared-key>, and empty elements
        if tag in _PANOS_TAGS or tag.endswith(_PANOS_SUFFIXES):
            if el.text != MASK:
                el.text = MASK
                count += 1
    return count


def count_fortios_policies(config: str) -> int:
    """Entries (``edit`` lines) directly inside ``config firewall policy``, in every VDOM."""
    stack: list[str] = []
    n = 0
    for line in config.splitlines():
        s = line.strip()
        if s.startswith("config "):
            stack.append(s[7:])
        elif s == "end" and stack:
            stack.pop()
        elif s.startswith("edit ") and stack and stack[-1] == "firewall policy":
            n += 1
    return n
