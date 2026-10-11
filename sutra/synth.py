"""Generate a realistic, fully synthetic estate and its scanner exports.

Writes three files into the output folder:

* ``qualys_vm_export.csv``  - a Qualys VM detection report (CSV, with Qualys' preamble)
* ``tenable_sc_export.csv`` - a Tenable.sc vulnerability export (CSV)
* ``cmdb_assets.csv``       - the customer's asset register

The organisation, hosts, IPs, QIDs, plugin IDs and advisory numbers are invented.
CVE IDs are real so that threat-intel lookups behave like they would on real data.
"""

from __future__ import annotations

import csv
import random
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path

ORG = "Demo Vindhya Power Ltd (SYNTHETIC)"
AS_OF = date(2026, 10, 5)

PROCESSES = {
    "gen": ("Unit-2 generation (250 MW)", 1_000_000),
    "chp": ("Coal handling plant", 300_000),
    "erp": ("SAP ERP and finance", 400_000),
    "portal": ("Customer billing portal", 250_000),
    "apps": ("Internal apps on Kubernetes", 150_000),
    "office": ("Corporate office productivity", 50_000),
    "remote": ("Remote access for staff and vendors", 120_000),
    "files": ("File and print services", 40_000),
    "net": ("Corporate network", 200_000),
    "solar": ("Solar park SCADA (40 MW)", 160_000),
}

SEV_QUALYS = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
SEV_TENABLE = {"info": "Info", "low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}


@dataclass
class Vuln:
    key: str
    style: str  # rpm | deb | app | kb | fw | config | cred
    title_q: str
    title_t: str
    qid: int
    plugin: int
    family: str
    sev: str
    cvss: float
    cves: list[str]
    solution: str
    pkg: str = ""
    installed: str = ""
    fixed: str = ""
    path: str = ""
    account: str = ""
    fingerprint: str = ""
    age_days: tuple[int, int] = (20, 400)


def rpm(key, pkg, inst, fixed, adv, qid, plugin, sev, cvss, cves, age=(30, 400)):
    return Vuln(key, "rpm", f"Red Hat Update for {pkg} ({adv})", f"RHEL 8 : {pkg} ({adv})", qid, plugin,
                "Red Hat Local Security Checks", sev, cvss, cves,
                f"Update {pkg} to {fixed} or later as described in {adv}.", pkg, inst, fixed, age_days=age)


def deb(key, pkg, inst, fixed, adv, qid, plugin, sev, cvss, cves, age=(30, 300)):
    return Vuln(key, "deb", f"Ubuntu Security Notification for {pkg} Vulnerabilities ({adv})",
                f"Ubuntu 20.04 LTS : {pkg} vulnerabilities ({adv})", qid, plugin, "Ubuntu Local Security Checks",
                sev, cvss, cves, f"Update {pkg} to {fixed} or later.", pkg, inst, fixed, age_days=age)


def app(key, name, inst, fixed, path, suffix, qid, plugin, family, sev, cvss, cves, age=(20, 400)):
    return Vuln(key, "app", f"{name} Prior to {fixed} {suffix}", f"{name} < {fixed} {suffix}", qid, plugin, family,
                sev, cvss, cves, f"Upgrade {name} to version {fixed} or later.", name, inst, fixed, path, age_days=age)


def kb(key, title, kbid, qid, plugin, sev, cvss, cves, age=(400, 900)):
    return Vuln(key, "kb", title, title + f" ({kbid}) (uncredentialed check)", qid, plugin, "Windows", sev, cvss, cves,
                f"Install Microsoft security update {kbid}.", "Microsoft Windows OS patch", "missing", kbid,
                age_days=age)


def config(key, title_q, title_t, qid, plugin, family, sev, cvss, solution, age=(60, 600)):
    return Vuln(key, "config", title_q, title_t, qid, plugin, family, sev, cvss, [], solution, age_days=age)


def cred(key, title_q, title_t, qid, plugin, family, sev, cvss, account, fp, solution, age=(90, 700)):
    return Vuln(key, "cred", title_q, title_t, qid, plugin, family, sev, cvss, [], solution, account=account,
                fingerprint=fp, age_days=age)


V = {v.key: v for v in [
    # rhel8-base-v3 golden image
    rpm("openssl8", "openssl", "1:1.1.1k-7.el8_6", "1:1.1.1k-12.el8_9", "RHSA-2023:1405", 241312, 173210, "high", 7.4,
        ["CVE-2023-0286", "CVE-2023-0215"]),
    rpm("openssh8", "openssh", "8.0p1-13.el8", "8.0p1-19.el8_8", "RHSA-2023:4419", 241790, 179104, "critical", 9.8,
        ["CVE-2023-38408"]),
    rpm("sudo8", "sudo", "1.8.29-8.el8", "1.8.29-9.el8", "RHSA-2023:0291", 241120, 170122, "high", 7.8,
        ["CVE-2023-22809"]),
    rpm("glibc8", "glibc", "2.28-211.el8", "2.28-236.el8_9.7", "RHSA-2023:5455", 242051, 182611, "high", 7.8,
        ["CVE-2023-4911"]),
    # ubuntu2004-k8s-node-v7 image
    deb("runc", "runc", "1.1.4-0ubuntu1~20.04.1", "1.1.12-0ubuntu2~20.04.1", "USN-6619-1", 199812, 189402, "high",
        8.6, ["CVE-2024-21626"]),
    deb("containerd", "containerd", "1.6.12-0ubuntu1~20.04.1", "1.7.2-0ubuntu1~20.04.1", "USN-6202-1", 199455,
        178002, "medium", 5.5, ["CVE-2023-25153", "CVE-2023-25173"]),
    deb("kernel2004", "linux-image-generic", "5.4.0.150.148", "5.4.0.170.168", "USN-6609-1", 199790, 189100, "high",
        7.8, ["CVE-2023-6932", "CVE-2023-6817"]),
    # win2019-std-tmpl-2023 VM template
    app("7zip", "7-Zip", "19.00", "23.01", r"C:\Program Files\7-Zip\7z.exe", "Multiple Vulnerabilities", 380622,
        180360, "Windows", "high", 7.8, ["CVE-2023-31102", "CVE-2023-40481"]),
    app("vmtools", "VMware Tools", "11.3.5", "12.3.5", r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe",
        "SAML Token Signature Bypass", 380901, 183884, "Windows", "high", 7.5, ["CVE-2023-34058"]),
    # win11-corp-2024q2 workstation image
    app("chrome", "Google Chrome", "124.0.6367.91", "125.0.6422.112",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe", "Multiple Vulnerabilities", 381450, 197831,
        "Windows", "high", 8.8, ["CVE-2024-4947", "CVE-2024-5274"], age=(120, 160)),
    app("acrobat", "Adobe Acrobat Reader DC", "23.008.20470", "24.002.20759",
        r"C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe", "Multiple Vulnerabilities (APSB24-29)", 381201,
        195110, "Windows", "high", 7.8, ["CVE-2024-30284", "CVE-2024-30310"], age=(150, 200)),
    # Fleet-wide packages that no image explains
    app("log4j", "Apache Log4j", "2.14.1", "2.17.1", "/opt/app/lib/log4j-core-2.14.1.jar",
        "Multiple Vulnerabilities (Log4Shell)", 730297, 156860, "Misc.", "critical", 10.0,
        ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105", "CVE-2021-44832"], age=(500, 900)),
    app("tomcat", "Apache Tomcat", "9.0.50", "9.0.83", "/opt/tomcat/lib/catalina.jar",
        "Multiple Vulnerabilities", 731010, 186365, "Web Servers", "high", 7.5, ["CVE-2023-46589", "CVE-2023-44487"]),
    app("citrix", "Citrix NetScaler ADC", "13.1-48.47", "13.1-49.15", "/netscaler/nsppe",
        "Information Disclosure (Citrix Bleed)", 380918, 183026, "CGI abuses", "critical", 9.4, ["CVE-2023-4966"],
        age=(18, 30)),
    app("jquery", "jQuery", "3.4.1", "3.5.0", "/var/www/static/js/jquery-3.4.1.min.js", "Multiple XSS", 11873,
        136929, "CGI abuses : XSS", "medium", 6.1, ["CVE-2020-11022", "CVE-2020-11023"]),
    # OT: vendor HMI image (Windows 7 Embedded), PLC firmware
    kb("bluekeep", "Microsoft Windows Remote Desktop Services Remote Code Execution Vulnerability (BlueKeep)",
       "KB4499175", 91541, 125313, "critical", 9.8, ["CVE-2019-0708"]),
    kb("ms17010", "Microsoft Windows SMB Server Remote Code Execution Vulnerability (MS17-010)", "KB4012212",
       91345, 97833, "critical", 8.1, ["CVE-2017-0144", "CVE-2017-0145"]),
    Vuln("s7fw", "fw", "Siemens SIMATIC S7-1500 CPU Prior to V3.0.1 Private Key Exposure (SSA-568427)",
         "Siemens SIMATIC S7-1500 CPU < V3.0.1 Private Key Exposure (SSA-568427)", 0, 503112, "SCADA", "critical",
         9.3, ["CVE-2022-38465"], "Upgrade CPU firmware to V3.0.1 or later after OEM approval and a planned outage.",
         "Siemens SIMATIC S7-1500 CPU", "V2.9.4", "V3.0.1", age_days=(300, 700)),
    # Configuration set by templates
    config("smbv1", "Microsoft SMBv1 Protocol Enabled", "Server Message Block (SMB) Protocol Version 1 Enabled",
           90954, 100464, "Windows", "medium", 5.9, "Disable SMBv1 in the server baseline."),
    config("tls10", "TLS Protocol Version 1.0 and 1.1 Enabled", "TLS Version 1.0 Protocol Detection", 38628,
           104743, "Service detection", "medium", 6.5, "Allow only TLS 1.2 and 1.3 in the web server role."),
    config("snmp", "SNMP Agent Default Community Name (public)", "SNMP Agent Default Community Name (public)",
           78030, 41028, "SNMP", "high", 7.5, "Replace the default community with SNMPv3 in the switch baseline."),
    config("selfsigned", "Self-Signed Certificate", "SSL Self-Signed Certificate", 38169, 57582, "General",
           "medium", 6.5, "Issue certificates from the internal CA."),
    config("trace", "HTTP TRACE / TRACK Methods Enabled", "HTTP TRACE / TRACK Methods Allowed", 86473, 11213,
           "Web Servers", "medium", 5.3, "Disable TRACE and TRACK in the web server configuration."),
    # Shared credentials
    cred("ntlmreuse", "Windows Local Administrator Password Reused Across Hosts (LAPS Not Deployed)",
         "Microsoft Windows Local Administrator Password Reuse", 105971, 160301, "Windows", "high", 8.1,
         "Administrator", "ntlm:7f3c9a51e2", "Deploy Windows LAPS so every host gets a unique admin password."),
    cred("hmidefault", "Default Vendor Credentials Accepted on HMI Web Interface",
         "Default Password 'engineer' for HMI Web Interface", 0, 502911, "SCADA", "critical", 9.8, "engineer",
         "vendor-default:engineer", "Change the vendor default account on every HMI and engineering workstation."),
]}


@dataclass
class Host:
    asset_id: str
    hostname: str
    ip: str
    site: str
    zone: str
    os: str
    owner: str
    process: str
    criticality: int
    image: str = ""
    template: str = ""
    is_ot: bool = False
    safety: bool = False
    pii: bool = False
    scanners: tuple[str, ...] = ("qualys", "tenable")
    in_cmdb: bool = True
    vulns: list[str] = field(default_factory=list)


def build_estate(rng: random.Random) -> list[Host]:
    hosts: list[Host] = []
    n = 0

    def add(count, name, ip, **kw):
        nonlocal n
        made = []
        for i in range(1, count + 1):
            n += 1
            h = Host(asset_id=f"AST-{n:04d}", hostname=name.format(i=i), ip=ip.format(i=i, a=i // 250, b=i % 250 + 1),
                     **kw)
            hosts.append(h)
            made.append(h)
        return made

    hq, plant, solar = "HQ Pune", "Vindhya Thermal Plant", "Solar Park Jodhpur"
    rhel_app = add(34, "pun-app-rhel-{i:03d}", "10.10.20.{i}", site=hq, zone="corp",
                   os="Red Hat Enterprise Linux 8.6", owner="IT Infra - Linux", process="erp", criticality=4,
                   image="rhel8-base-v3", pii=True)
    rhel_dmz = add(6, "dmz-web-{i:02d}", "172.16.10.{i}", site=hq, zone="dmz", os="Red Hat Enterprise Linux 8.6",
                   owner="Digital - Portal", process="portal", criticality=4, image="rhel8-base-v3",
                   template="ansible-role-nginx-v2", pii=True)
    k8s = add(25, "pun-k8s-node-{i:02d}", "10.10.30.{i}", site=hq, zone="corp", os="Ubuntu 20.04.6 LTS",
              owner="Platform Engineering", process="apps", criticality=3, image="ubuntu2004-k8s-node-v7")
    winsrv = add(30, "pun-win-srv-{i:02d}", "10.10.40.{i}", site=hq, zone="corp",
                 os="Windows Server 2019 Standard", owner="IT Infra - Windows", process="erp", criticality=3,
                 image="win2019-std-tmpl-2023")
    for h in winsrv[:14]:
        h.template, h.process = "GPO-Legacy-FileServers", "files"
    laptops = add(80, "lt-pun-{i:04d}", "10.20.{a}.{b}", site=hq, zone="corp", os="Windows 11 Enterprise 23H2",
                  owner="End-user Computing", process="office", criticality=1, image="win11-corp-2024q2",
                  scanners=("qualys",))
    webs = add(6, "pun-web-{i:02d}", "10.10.50.{i}", site=hq, zone="corp", os="Ubuntu 22.04.4 LTS",
               owner="Digital - Portal", process="portal", criticality=3, template="ansible-role-nginx-v2")
    adcs = add(2, "edge-adc-{i:02d}", "203.0.113.{i}", site=hq, zone="internet", os="Citrix NetScaler ADC 13.1",
               owner="Network Security", process="remote", criticality=4)
    switches = add(20, "sw-pun-{i:02d}", "10.10.0.{i}", site=hq, zone="corp", os="Cisco IOS 15.2(7)E",
                   owner="Network Operations", process="net", criticality=3, template="switch-baseline-2019")
    hmis = add(10, "vtp-hmi-{i:02d}", "192.168.50.{i}", site=plant, zone="ot-l2", os="Windows 7 Embedded SP1",
               owner="C&I - Unit 2", process="gen", criticality=5, image="hmi-win7e-vendor-2016", is_ot=True,
               safety=True, scanners=("tenable",))
    ews = add(4, "vtp-ews-{i:02d}", "192.168.40.{i}", site=plant, zone="ot-l3", os="Windows 10 Enterprise LTSC 2019",
              owner="C&I - Unit 2", process="gen", criticality=5, is_ot=True, safety=True, scanners=("tenable",))
    plcs = add(12, "vtp-plc-{i:02d}", "192.168.60.{i}", site=plant, zone="ot-l1",
               os="Siemens SIMATIC S7-1500 CPU 1516-3 PN/DP", owner="C&I - Unit 2", process="gen", criticality=5,
               is_ot=True, safety=True, scanners=("tenable",))
    for h in plcs[6:]:
        h.process, h.owner = "chp", "C&I - Coal Handling"
    # Scanned but missing from the CMDB: build boxes cloned from the RHEL image, plus two strays.
    strays = add(7, "tmp-build-{i:02d}", "10.10.20.{i}", site=hq, zone="corp", os="Red Hat Enterprise Linux 8.6",
                 owner="", process="", criticality=3, image="rhel8-base-v3", in_cmdb=False)
    for i, h in enumerate(strays):
        h.ip = f"10.10.20.{200 + i}"
    strays += add(2, "desktop-{i}kq2la", "10.10.70.{i}", site=hq, zone="corp", os="Windows Server 2016 Standard",
                  owner="", process="", criticality=3, in_cmdb=False)
    # In the CMDB but never scanned: blind spots.
    add(8, "jdh-rtu-{i:02d}", "192.168.80.{i}", site=solar, zone="ot-l2", os="RTU firmware 4.2", owner="Solar O&M",
        process="solar", criticality=4, is_ot=True, safety=True, scanners=())
    add(4, "pun-db-ora-{i:02d}", "10.10.25.{i}", site=hq, zone="corp", os="Oracle Linux 7.9", owner="DBA team",
        process="erp", criticality=5, pii=True, scanners=())

    def give(group, keys, p=0.9):
        for h in group:
            for k in keys:
                if rng.random() < p:
                    h.vulns.append(k)

    rhel_image = ["openssl8", "openssh8", "sudo8", "glibc8"]
    give(rhel_app + rhel_dmz + strays[:7], rhel_image)
    give(k8s, ["runc", "containerd", "kernel2004"])
    give(winsrv, ["7zip", "vmtools"])
    give(laptops, ["chrome", "acrobat"], p=0.85)
    give(hmis, ["bluekeep", "ms17010"], p=1.0)
    give(plcs, ["s7fw"], p=1.0)
    give(adcs, ["citrix"], p=1.0)
    give(switches, ["snmp"], p=0.9)
    give(webs + rhel_dmz, ["tls10"], p=1.0)
    for h in winsrv[:14] + winsrv[20:23]:
        h.vulns.append("smbv1")
    for h in winsrv[:22]:
        h.vulns.append("ntlmreuse")
    for h in hmis + ews:
        h.vulns.append("hmidefault")
    for h in [rhel_app[4], rhel_app[10], rhel_app[16], winsrv[18], winsrv[25], strays[7]]:
        h.vulns.append("log4j")
    for h in [rhel_app[2], rhel_app[8], rhel_app[21], rhel_app[27], webs[1]]:
        h.vulns.append("tomcat")
    # Long tail of small, unrelated findings.
    tail = ["selfsigned", "trace", "jquery"]
    for h in rhel_app + k8s + winsrv + webs + strays:
        if rng.random() < 0.18:
            h.vulns.append(rng.choice(tail))
    return hosts


def _detected(rng: random.Random, v: Vuln) -> tuple[datetime, datetime]:
    first = AS_OF - timedelta(days=rng.randint(*v.age_days))
    first_dt = datetime(first.year, first.month, first.day, rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59))
    last_dt = datetime(AS_OF.year, AS_OF.month, AS_OF.day, rng.randint(1, 6), rng.randint(0, 59), rng.randint(0, 59))
    return first_dt, last_dt


def _qualys_results(v: Vuln) -> str:
    if v.style == "rpm":
        return f"Package\tInstalled Version\tRequired Version\n{v.pkg}\t{v.installed}\t{v.fixed}"
    if v.style == "deb":
        return f"Package\tInstalled Version\tRequired Version\n{v.pkg}\t{v.installed}\t{v.fixed}"
    if v.style == "app":
        return f"{v.path} Version is {v.installed}#"
    if v.style == "kb":
        return f"{v.fixed} is not installed"
    if v.style == "config":
        return {"smbv1": "SMBv1 is enabled: HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters SMB1 = 1",
                "tls10": "TLSv1.0 is supported\nTLSv1.1 is supported",
                "snmp": "Community name: public",
                "selfsigned": "Certificate #0 CN=localhost is self-signed",
                "trace": "TRACE / HTTP/1.1 returned 200"}[v.key]
    if v.style == "cred":
        return f"Account: {v.account}\nCredential fingerprint: {v.fingerprint}"
    return ""


def _tenable_output(v: Vuln) -> str:
    if v.style in ("rpm", "deb"):
        inst = v.installed.split(":", 1)[-1]
        fixed = v.fixed.split(":", 1)[-1]
        sep = "-" if v.style == "rpm" else "_"
        return (f"\n  Remote package installed : {v.pkg}{sep}{inst}\n"
                f"  Should be                : {v.pkg}{sep}{fixed}\n")
    if v.style == "app":
        return f"\n  Path              : {v.path}\n  Installed version : {v.installed}\n  Fixed version     : {v.fixed}\n"
    if v.style == "fw":
        return f"\n  Model             : 6ES7516-3AN02-0AB0\n  Installed firmware : {v.installed}\n  Fixed firmware     : {v.fixed}\n"
    if v.style == "kb":
        return f"\nThe remote host is missing one of the following security updates :\n  - {v.fixed}\n"
    if v.style == "config":
        return _qualys_results(v)
    if v.style == "cred":
        return f"\nIt was possible to log in with the following credentials :\n  Account : {v.account}\n  Credential fingerprint : {v.fingerprint}\n"
    return ""


QUALYS_COLS = ["IP", "DNS", "NetBIOS", "OS", "IP Status", "QID", "Title", "Type", "Severity", "Port", "Protocol",
               "FQDN", "SSL", "First Detected", "Last Detected", "Times Detected", "CVE ID", "Vendor Reference",
               "CVSS3.1 Base", "Threat", "Impact", "Solution", "Results", "PCI Vuln", "Category"]
TENABLE_COLS = ["Plugin", "Plugin Name", "Family", "Severity", "IP Address", "Protocol", "Port", "Exploit?",
                "DNS Name", "NetBIOS Name", "Plugin Output", "Synopsis", "Description", "Solution", "See Also",
                "CVSS V3 Base Score", "CVE", "First Discovered", "Last Observed", "Exploit Frameworks"]
CMDB_COLS = ["asset_id", "hostname", "ip", "site", "zone", "os", "owner", "business_process", "inr_per_hour",
             "criticality", "image", "config_template", "is_ot", "safety_critical", "personal_data"]

PORTS = {"config": {"smbv1": ("445", "tcp"), "tls10": ("443", "tcp"), "snmp": ("161", "udp"),
                    "selfsigned": ("8443", "tcp"), "trace": ("80", "tcp")},
         "cred": {"ntlmreuse": ("445", "tcp"), "hmidefault": ("443", "tcp")},
         "kb": {"bluekeep": ("3389", "tcp"), "ms17010": ("445", "tcp")}}


def _port(v: Vuln) -> tuple[str, str]:
    if v.key in ("citrix", "jquery"):
        return "443", "tcp"
    if v.style == "fw":
        return "102", "tcp"
    return PORTS.get(v.style, {}).get(v.key, ("0", "tcp"))


def generate(out_dir: Path, seed: int = 7) -> dict[str, Path]:
    rng = random.Random(seed)
    out_dir.mkdir(parents=True, exist_ok=True)
    hosts = build_estate(rng)
    paths = {"qualys": out_dir / "qualys_vm_export.csv", "tenable": out_dir / "tenable_sc_export.csv",
             "cmdb": out_dir / "cmdb_assets.csv"}

    with paths["cmdb"].open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(CMDB_COLS)
        for h in hosts:
            if not h.in_cmdb:
                continue
            name, inr = PROCESSES[h.process]
            w.writerow([h.asset_id, h.hostname, h.ip, h.site, h.zone, h.os, h.owner, name, inr, h.criticality,
                        h.image, h.template, int(h.is_ot), int(h.safety), int(h.pii)])

    q_rows, t_rows = [], []
    for h in hosts:
        fqdn = f"{h.hostname}.corp.example.in"
        scan_dt = datetime(AS_OF.year, AS_OF.month, AS_OF.day, 2, rng.randint(0, 59), rng.randint(0, 59))
        if "qualys" in h.scanners:
            q_rows.append([h.ip, fqdn, h.hostname.upper()[:15], h.os, "host scanned, found vuln", 45038,
                           "Host Scan Time - Scanner", "Ig", 1, "", "", fqdn, "", scan_dt.strftime("%m/%d/%Y %H:%M:%S"),
                           scan_dt.strftime("%m/%d/%Y %H:%M:%S"), 1, "", "", "", "", "", "",
                           "Scan duration: 412 seconds", "no", "Information gathering"])
        if "tenable" in h.scanners:
            t_rows.append([19506, "Nessus Scan Information", "Settings", "Info", h.ip, "TCP", "0", "No", fqdn,
                           h.hostname.upper()[:15], "Credentialed checks : yes", "", "", "", "", "", "",
                           scan_dt.strftime("%b %d, %Y %H:%M:%S UTC"), scan_dt.strftime("%b %d, %Y %H:%M:%S UTC"), ""])
        for key in h.vulns:
            v = V[key]
            first, last = _detected(rng, v)
            port, proto = _port(v)
            if "qualys" in h.scanners and v.qid:
                q_rows.append([h.ip, fqdn, h.hostname.upper()[:15], h.os, "host scanned, found vuln", v.qid,
                               v.title_q, "Practice" if v.style in ("config", "cred") else "Vuln",
                               SEV_QUALYS[v.sev], port, proto, fqdn, "", first.strftime("%m/%d/%Y %H:%M:%S"),
                               last.strftime("%m/%d/%Y %H:%M:%S"), rng.randint(3, 60), ", ".join(v.cves), "",
                               v.cvss, "See vendor advisory.", "Compromise of the affected host.", v.solution,
                               _qualys_results(v), "yes" if v.sev in ("high", "critical") else "no", v.family])
            if "tenable" in h.scanners and v.plugin:
                exploit = "Yes" if v.sev == "critical" or key in ("glibc8", "runc", "chrome", "sudo8") else "No"
                t_rows.append([v.plugin, v.title_t, v.family, SEV_TENABLE[v.sev], h.ip, proto.upper(), port, exploit,
                               fqdn, h.hostname.upper()[:15], _tenable_output(v), v.title_t, v.title_t, v.solution,
                               "", v.cvss, ",".join(v.cves), first.strftime("%b %d, %Y %H:%M:%S UTC"),
                               last.strftime("%b %d, %Y %H:%M:%S UTC"),
                               "Metasploit" if exploit == "Yes" and v.sev == "critical" else ""])

    rng.shuffle(q_rows)
    rng.shuffle(t_rows)
    with paths["qualys"].open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["Scan Results", f"{AS_OF:%m/%d/%Y} at 06:00:00 (GMT+0530)"])
        w.writerow([ORG, "Report: Sutra prototype synthetic detections"])
        w.writerow([])
        w.writerow(QUALYS_COLS)
        w.writerows(q_rows)
    with paths["tenable"].open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(TENABLE_COLS)
        w.writerows(t_rows)
    return paths
