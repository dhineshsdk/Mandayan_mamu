"""Firewall and switch configuration collectors. Fixtures and their sources: ``fixtures/netdevices/README.md``."""

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import paramiko
import pytest

from sutra_connectors.cisco_ios import CiscoIosCollector, parse_arp, parse_mac_table, parse_version
from sutra_connectors.errors import (
    ApiError,
    AuthenticationError,
    ConfigurationError,
    HostKeyError,
    ReadOnlyViolation,
)
from sutra_connectors.fortigate import FortiGateCollector
from sutra_connectors.http import RetryPolicy
from sutra_connectors.netdevices import MacEntry, config_digest, mask_fortios, mask_ios, norm_mac
from sutra_connectors.panos import SYSTEM_INFO, PanOsCollector
from sutra_connectors.ssh import CliSession, fingerprint

FIX = Path(__file__).parent / "fixtures" / "netdevices"
NOW = datetime(2026, 10, 11, 6, 0, tzinfo=timezone.utc)
RETRY = RetryPolicy(max_attempts=2, backoff_base=0)


def text(name):
    return (FIX / name).read_text()


# ---------- FortiGate ----------

class FakeFortiGate:
    def __init__(self, config=None, status=200, backup_json=None):
        self.requests = []
        self.config = config if config is not None else text("fortios_firewall_policy.conf")
        self.status, self.backup_json = status, backup_json

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        if self.status != 200:
            return httpx.Response(self.status, json={"status": "error"})
        if req.url.path == "/api/v2/monitor/system/status":
            return httpx.Response(200, json=json.loads(text("fortigate_status.json")))
        if self.backup_json is not None:
            return httpx.Response(200, json=self.backup_json)
        return httpx.Response(200, text=self.config, headers={"content-type": "application/octet-stream"})


def fortigate(fake, **kw):
    return FortiGateCollector("https://fw1.plant.example", "tok-123", transport=httpx.MockTransport(fake),
                              sleep=lambda s: None, clock=lambda: NOW, retry=RETRY, **kw)


def test_fortigate_reads_status_and_full_backup():
    fake = FakeFortiGate()
    snap = fortigate(fake).collect()
    status, backup = fake.requests
    assert status.headers["authorization"] == "Bearer tok-123"
    assert backup.url.path == "/api/v2/monitor/system/config/backup"
    assert dict(backup.url.params) == {"scope": "global", "destination": "file", "password_mask": "true"}
    assert snap.vendor == "Fortinet FortiGate" and snap.source == "fortigate-api:fw1.plant.example"
    assert (snap.hostname, snap.serial, snap.version) == ("firewall_policy", "FGT60FTK00000000", "v7.2.8")
    assert snap.model == "FortiGate 60F" and snap.config_format == "fortios" and snap.collected_at == NOW
    # Batfish's file has five rules, one of them disabled.
    assert snap.facts == {"firewall_policies": 5}
    assert snap.masked == 0 and snap.config == text("fortios_firewall_policy.conf")


def test_fortigate_masks_secrets_before_returning():
    secrets = "\n".join([
        "config system admin", '    edit "admin"', "        set password ENC SH2nlSm9pHsMdbV4Mm5/0FU7Uf6SsAA=",
        "    next", "end",
        "config vpn ipsec phase1-interface", '    edit "to-dc"', "        set psksecret ENC kZ9b0Yy3+Lw==",
        "        set keylife 28800", "    next", "end",
        "config system snmp community", "    edit 1", '        set name "plantRO"', "    next", "end",
        "config vpn certificate local", '    edit "web"',
        '        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----',
        "MIIFHzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQI", '-----END ENCRYPTED PRIVATE KEY-----"',
        '        set certificate "-----BEGIN CERTIFICATE-----', "MIIDdzCCAl+gAwIBAgIE", '-----END CERTIFICATE-----"',
        "    next", "end",
        "config user local", '    edit "guest"', "        set type password", "        set passwd ENC abc+def==",
        "    next", "end", ""])
    masked, n = mask_fortios(secrets)
    assert n == 5
    for gone in ("SH2nlSm9", "kZ9b0Yy3", "plantRO", "MIIFHzBJ", "abc+def"):
        assert gone not in masked
    assert "set password ENC SUTRA-MASKED" in masked and "set private-key SUTRA-MASKED" in masked
    # Settings that only look like secrets stay: the IPsec key lifetime, a public certificate, the user type.
    assert "set keylife 28800" in masked and "MIIDdzCCAl+gAwIBAgIE" in masked and "set type password" in masked
    assert mask_fortios(masked) == (masked, 0)  # masking twice changes nothing


def test_fortigate_errors():
    with pytest.raises(AuthenticationError):
        fortigate(FakeFortiGate(status=401)).collect()
    with pytest.raises(ApiError, match="refused"):
        fortigate(FakeFortiGate(backup_json={"status": "error", "http_status": 403})).collect()
    with pytest.raises(ApiError, match="not a FortiOS configuration"):
        fortigate(FakeFortiGate(config="<html>login</html>")).collect()
    with pytest.raises(ConfigurationError):
        FortiGateCollector("http://fw1", "t")
    with pytest.raises(ReadOnlyViolation):
        fortigate(FakeFortiGate()).http.request("POST", "/api/v2/monitor/system/config/backup",
                                                params={"scope": "global"})
    with pytest.raises(ReadOnlyViolation):
        fortigate(FakeFortiGate()).http.request("GET", "/api/v2/cmdb/system/admin")


# ---------- PAN-OS ----------

class FakePanOs:
    def __init__(self, config_status="success", code=None):
        self.requests = []
        self.config_status, self.code = config_status, code

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        form = {k: v[0] for k, v in parse_qs(req.content.decode()).items()}
        if form["type"] == "op":
            return httpx.Response(200, text=text("panos_system_info.xml"))
        if self.config_status != "success":
            code = f' code="{self.code}"' if self.code else ""
            return httpx.Response(200, text=f'<response status="error"{code}><msg><line>Invalid credentials.</line>'
                                            "</msg></response>")
        return httpx.Response(200, text='<response status="success"><result total="1" count="1">'
                                        + text("panos_iron_skillet_full.xml") + "</result></response>")


def panos(fake):
    return PanOsCollector("https://pa.dc.example", "LUFRPT1-key", transport=httpx.MockTransport(fake),
                          sleep=lambda s: None, clock=lambda: NOW, retry=RETRY)


def test_panos_reads_system_info_and_running_config():
    fake = FakePanOs()
    snap = panos(fake).collect()
    forms = [{k: v[0] for k, v in parse_qs(r.content.decode()).items()} for r in fake.requests]
    assert all(r.method == "POST" and r.url.path == "/api/" for r in fake.requests)
    assert forms[0] == {"type": "op", "cmd": SYSTEM_INFO, "key": "LUFRPT1-key"}
    assert forms[1] == {"type": "config", "action": "show", "xpath": "/config", "key": "LUFRPT1-key"}
    assert (snap.hostname, snap.model, snap.serial, snap.version) == ("pa-dc-01", "PA-3220", "000000000000",
                                                                    "10.1.11-h4")
    assert snap.config.startswith('<config version="10.1.0"') and snap.config_format == "panos-xml"
    assert "\n  <mgt-config>\n    <users>\n" in snap.config  # one element per line, so changes diff by line
    assert snap.facts == {"security_rules": 2}  # Iron Skillet's outbound and inbound block rules
    # The administrator's password hash is masked; the <api><key> container (key lifetime settings) is not text.
    assert snap.masked == 1 and "md5_hash" not in snap.config and "<phash>SUTRA-MASKED</phash>" in snap.config


def test_panos_errors_and_allowlist():
    with pytest.raises(ApiError, match="Invalid credentials"):
        panos(FakePanOs(config_status="error")).collect()
    with pytest.raises(AuthenticationError):
        panos(FakePanOs(config_status="error", code="403")).collect()
    c = panos(FakePanOs())
    with pytest.raises(ReadOnlyViolation):  # a commit, or any other operational command, is refused
        c.http.request("POST", "/api/", data={"type": "commit", "cmd": "<commit></commit>"})
    with pytest.raises(ReadOnlyViolation):
        c.http.request("POST", "/api/", data={"type": "op", "cmd": "<request><restart><system/></restart></request>"})
    with pytest.raises(ReadOnlyViolation):
        c.http.request("POST", "/api/", data={"type": "config", "action": "set", "xpath": "/config"})


# ---------- Cisco IOS over SSH ----------

class FakeKey:
    def __init__(self, fp="SHA256:ycS795wsjuIr0nSPSIF04ZIYVyiDxObuAAu8w9eJlX8"):
        self.fingerprint = fp


class FakeChannel:
    """Answers like an IOS shell: echo, output with CRLF line ends, then the prompt; in small chunks."""

    def __init__(self, outputs, prompt, more=False):
        self.outputs, self.prompt, self.more = outputs, prompt, more
        self.queue, self.sent, self.pending = bytearray(), [], b""

    def settimeout(self, t):
        pass

    def send(self, s):
        self.sent.append(s)
        if s == "\n":
            self.queue += f"\r\n\r\nUser Access Verification\r\n\r\n{self.prompt}\r\n{self.prompt}".encode()
        elif s == " ":
            self.queue += self.pending
            self.pending = b""
        else:
            cmd = s.rstrip("\n")
            out = self.outputs.get(cmd, "").replace("\n", "\r\n")
            data = f"{cmd}\r\n{out}\r\n{self.prompt}".encode()
            if self.more and cmd == "show running-config":
                cut = len(data) // 2
                data, self.pending = data[:cut] + b"\r\n --More-- ", data[cut:]
            self.queue += data

    def recv(self, n):
        if not self.queue:
            raise TimeoutError()
        take = min(n, 37)
        data = bytes(self.queue[:take])
        del self.queue[:take]
        return data


class FakeClient:
    def __init__(self, channel, key=None, auth_ok=True):
        self.channel, self.key, self.auth_ok = channel, key or FakeKey(), auth_ok
        self.connected, self.closed = None, False

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, host, **kw):
        self.connected = (host, kw)
        self.policy.missing_host_key(self, host, self.key)
        if not self.auth_ok:
            raise paramiko.AuthenticationException("Authentication failed.")

    def invoke_shell(self, **kw):
        return self.channel

    def close(self):
        self.closed = True


IOS_OUTPUTS = {
    "terminal width 511": "",
    "terminal length 0": "",
    "show version": text("ios_show_version_cat4500.raw"),
    "show running-config": "Building configuration...\n\nCurrent configuration : 3706 bytes\n"
                           + text("ios_as1border1.cfg"),
    "show ip arp": text("ios_show_ip_arp.raw"),
    "show mac address-table": text("ios_show_mac_address_table4.raw"),
}


def ios(channel, client=None, **kw):
    client = client or FakeClient(channel)
    return CiscoIosCollector("10.20.0.2", "sutra-ro", "pw", client_factory=lambda: client, clock=lambda: NOW,
                             **kw), client


def test_cisco_collects_config_version_arp_and_mac_table():
    chan = FakeChannel(IOS_OUTPUTS, "as1border1#")
    collector, client = ios(chan)
    snap = collector.collect()
    host, kw = client.connected
    assert host == "10.20.0.2" and kw["look_for_keys"] is False and kw["allow_agent"] is False
    assert chan.sent == ["\n"] + [c + "\n" for c in IOS_OUTPUTS]
    assert snap.vendor == "Cisco IOS" and snap.source == "cisco-ios-ssh:10.20.0.2"
    assert (snap.hostname, snap.version, snap.model, snap.serial) == ("as1border1", "12.2(54)SG1", "WS-C4948E",
                                                                     "CAT1451S15C")
    assert snap.config.rstrip().endswith("end") and "hostname as1border1" in snap.config
    assert "Building configuration" in snap.config and "\r" not in snap.config
    assert snap.host_key == "SHA256:ycS795wsjuIr0nSPSIF04ZIYVyiDxObuAAu8w9eJlX8"
    assert [(a.ip, a.mac, a.interface) for a in snap.arp] == [("172.16.168.254", "00:00:0c:36:69:65",
                                                               "Ethernet0/0")]
    # Table 4 has 11 learned entries; its STATIC CPU entries are the switch's own and are left out.
    assert len(snap.mac_table) == 11 and snap.mac_table[0] == MacEntry("30:a3:30:a3:a1:c3", "1", "Po1")


def test_cisco_answers_a_pager_prompt():
    chan = FakeChannel(IOS_OUTPUTS, "as1border1#", more=True)
    snap = ios(chan)[0].collect()
    assert " " in chan.sent and "--More--" not in snap.config and "hostname as1border1" in snap.config


def test_cisco_needs_privileged_exec():
    collector, _ = ios(FakeChannel(IOS_OUTPUTS, "as1border1>"))
    with pytest.raises(ConfigurationError, match="privilege level 15"):
        collector.collect()


def test_cisco_rejected_running_config():
    outputs = {**IOS_OUTPUTS, "show running-config": "Command authorization failed."}
    with pytest.raises(ApiError, match="did not return a configuration"):
        ios(FakeChannel(outputs, "sw1#"))[0].collect()
    # A router without a MAC table answers "% Invalid input"; that is no entries, not a failure.
    outputs = {**IOS_OUTPUTS, "show mac address-table": "                ^\n% Invalid input detected at '^' marker."}
    assert ios(FakeChannel(outputs, "as1border1#"))[0].collect().mac_table == ()


def test_host_key_is_pinned():
    chan = FakeChannel(IOS_OUTPUTS, "as1border1#")
    collector, client = ios(chan, host_key="SHA256:somethingelse")
    with pytest.raises(HostKeyError, match="not the pinned"):
        collector.collect()
    assert client.closed
    pinned = ios(FakeChannel(IOS_OUTPUTS, "as1border1#"), host_key="SHA256:ycS795wsjuIr0nSPSIF04ZIYVyiDxObuAAu8w9eJlX8")
    assert pinned[0].collect().hostname == "as1border1"
    with pytest.raises(ConfigurationError):
        CiscoIosCollector("h", "u", "p", host_key="MD5:aa:bb")


def test_fingerprint_is_the_openssh_form():
    key = paramiko.RSAKey.generate(1024)
    assert fingerprint(key) == key.fingerprint and key.fingerprint.startswith("SHA256:")


def test_ssh_login_failure_and_command_allowlist():
    chan = FakeChannel(IOS_OUTPUTS, "sw1#")
    with pytest.raises(AuthenticationError, match="refused the user name or password"):
        ios(chan, client=FakeClient(chan, auth_ok=False))[0].collect()
    s = CliSession("Cisco IOS", "h", "u", "p", allow=("show version",), client_factory=lambda: FakeClient(chan))
    s.open()
    for cmd in ("configure terminal", "reload", "copy running-config startup-config", "write memory"):
        with pytest.raises(ReadOnlyViolation):
            s.run(cmd)


def test_ssh_times_out_without_a_prompt():
    class Silent(FakeChannel):
        def send(self, s):
            self.sent.append(s)

    ticks = iter(range(0, 1000, 10))
    s = CliSession("Cisco IOS", "h", "u", "p", allow=(), timeout=30, client_factory=lambda: FakeClient(Silent({}, "")),
                   clock=lambda: next(ticks))
    with pytest.raises(ApiError, match="did not return to the prompt"):
        s.open()


def test_version_parsing_for_ios_xe():
    assert parse_version(text("ios_show_version_cat3k.raw")) == ("03.06.05E", "WS-C3850-48U", "FOC11111111")


def test_mac_table_layouts():
    two = parse_mac_table(text("ios_show_mac_address_table2.raw"))
    assert two[0].mac == "30:a3:30:a3:a1:c3" and two[0].vlan == "666" and two[0].port == "Te1/30"
    three = parse_mac_table(text("ios_show_mac_address_table3.raw"))
    assert (three[1].vlan, three[1].port) == ("99", "Port-channel1")
    assert all(e.mac and e.port for e in two + three)


def test_arp_parsing_skips_own_and_incomplete():
    sample = ("Protocol  Address          Age (min)  Hardware Addr   Type   Interface\n"
              "Internet  10.1.1.1                -   aabb.cc00.0100  ARPA   Vlan10\n"
              "Internet  10.1.1.20              12   0050.56a1.0b2c  ARPA   Vlan10\n"
              "Internet  10.1.1.21               0   Incomplete      ARPA\n")
    assert [(a.ip, a.mac, a.interface) for a in parse_arp(sample)] == [("10.1.1.20", "00:50:56:a1:0b:2c", "Vlan10")]


def test_ios_masking():
    config = "\n".join([
        "service password-encryption", "password encryption aes",
        "enable secret 9 $9$nhEmQVczB7dqsO$X.HsgL6x1il0RxkOSSvyQYwucySCt7qFm4v7pqCxkKM",
        "username netops privilege 15 secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0",
        "snmp-server community pUbL1c RO 10", "snmp-server community s3cr3tRW RW",
        "tacacs-server host 10.0.0.9 key 7 0822455D0A16",
        "tacacs server ISE", " address ipv4 10.0.0.10", " key 7 070C285F4D06",
        "radius server R1", " key PlainRadiusKey",
        "key chain OSPF", " key 1", "  key-string 7 104D000A0618",
        "interface Gi0/1", " ip ospf authentication-key 7 01100F175804",
        " ip ospf message-digest-key 1 md5 7 13061E010803",
        "ntp authentication-key 1 md5 121A0C041104 7",
        "crypto isakmp key 0 Sup3rPSK address 203.0.113.9",
        "router bgp 65001", " neighbor 10.0.0.1 password 7 045802150C2E", " neighbor as1 send-community",
        "line vty 0 4", " password 7 0822455D0A16", " transport input ssh", "end", ""])
    masked, n = mask_ios(config)
    for gone in ("$9$nhEm", "$1$mERr", "pUbL1c", "s3cr3tRW", "0822455D0A16", "070C285F4D06", "PlainRadiusKey",
                 "104D000A0618", "01100F175804", "13061E010803", "121A0C041104", "Sup3rPSK", "045802150C2E"):
        assert gone not in masked, gone
    assert n == 14
    for kept in ("service password-encryption", "password encryption aes", "enable secret 9 SUTRA-MASKED",
                 "snmp-server community SUTRA-MASKED RO 10", " key 1\n", "neighbor as1 send-community",
                 "tacacs-server host 10.0.0.9 key 7 SUTRA-MASKED", "transport input ssh"):
        assert kept in masked, kept
    assert mask_ios(masked) == (masked, 0)
    assert mask_ios(text("ios_as1border1.cfg"))[1] == 0  # Batfish's file has communities in route maps only


def test_digest_ignores_lines_devices_rewrite():
    a = "Building configuration...\n\nCurrent configuration : 100 bytes\n! Last configuration change at 10:00\n" \
        "ntp clock-period 17179861\nhostname sw1\nend\n"
    b = "Building configuration...\n\nCurrent configuration : 101 bytes\n! Last configuration change at 11:00\n" \
        "ntp clock-period 17179900\nhostname sw1\nend\n"
    assert config_digest(a, "ios") == config_digest(b, "ios")
    assert config_digest(a, "ios") != config_digest(a.replace("sw1", "sw2"), "ios")
    assert config_digest("#config-version=x\nconfig system global\nend", "fortios") == config_digest(
        "#config-version=y\nconfig system global\nend", "fortios")


def test_norm_mac():
    assert norm_mac("0000.0C59.F892") == norm_mac("00-00-0c-59-f8-92") == "00:00:0c:59:f8:92"
    assert norm_mac("Incomplete") == "" and norm_mac("0000.0c59") == ""
