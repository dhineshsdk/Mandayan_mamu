# Firewall and switch configuration: research notes for read-only collectors

Research date: 2026-10-11. The vendors' own reference sites (docs.fortinet.com, docs.paloaltonetworks.com) could not
be reached from the build environment, so they were not read. These sources were used instead:

- [FTNT-ANS]: Fortinet's Ansible collection for FortiOS, `fortinet-ansible-dev/ansible-galaxy-fortios-collection` on
  GitHub, branch `main`: `plugins/modules/fortios_monitor_fact.py`, `plugins/httpapi/fortios.py` and
  `plugins/module_utils/fortios/fortios.py`.
- [FTNT-PY]: `fortiosapi` 1.0.5 (PyPI), Fortinet's Python client, and its test `tests/test_fortiosapi_virsh.py`.
- [PAN-PY]: `pan-python` 0.26.0 (PyPI), Palo Alto Networks' XML API client: `pan/xapi.py` and the `panxapi.py` script's
  help text.
- [PAN-OS-PY]: `pan-os-python` 1.13.1 (PyPI): `panos/base.py`.
- [NETMIKO]: Netmiko 4.8.0 (PyPI): `netmiko/cisco/cisco_ios.py`, `netmiko/base_connection.py`.
- [NTC]: Network to Code's `ntc-templates` 9.3.0 (PyPI) TextFSM templates and the raw device outputs in its GitHub
  test suite.
- [BATFISH]: Batfish's FortiOS and Cisco IOS test configurations (GitHub), used as fixtures.

## FortiGate (FortiOS REST API)

- Auth: REST API administrator token as `Authorization: Bearer <token>` [FTNT-ANS httpapi; FTNT-PY `tokenlogin`].
- `GET /api/v2/monitor/system/config/backup` with `scope=global` (required), `destination=file`, `password_mask=true`
  [FTNT-ANS lists `scope` (required), `destination`, `vdom`, `password_mask`, `file_format`; FTNT-PY's test sends
  `destination=file&scope=global`]. The response body is the configuration file. `scope=global` covers every VDOM.
- `GET /api/v2/monitor/system/status` [FTNT-ANS]. The JSON envelope carries `version` [FTNT-PY reads it from every
  login response]; `serial` and `build` in the envelope are as remembered. DOC GAP: the `results` fields
  (`hostname`, `model_name`, `model_number`) are as remembered; the host name is read from `set hostname` in the
  configuration first, which is standard FortiOS CLI syntax.
- Role: an administrator profile with read access is enough for both calls (as remembered; confirm with a design
  partner).

`password_mask=true` asks FortiOS to mask secrets in the file. Sutra masks them again itself (any `set` of a password,
passwd, psksecret, secret, private key or similar, any `ENC` value, and SNMP community names), so a FortiOS version
that ignores the parameter still stores no secret.

## Palo Alto Networks firewalls (PAN-OS XML API)

- Every request is `POST /api/` with a form body; the API key goes in the `key` field [PAN-PY `__api_request`:
  POST unless `use_get`, `key` added to the body]. Keeping the key in the body keeps it out of URLs and logs.
- `type=op&cmd=<show><system><info></info></system></show>` [PAN-OS-PY `show_system_info` runs `show system info`
  with `cmd_xml=True`]. Fields read: `result/system/sw-version`, `model`, `serial` [PAN-OS-PY]; `hostname` as
  remembered, with the configuration's `deviceconfig/system/hostname` as fallback.
- `type=config&action=show&xpath=/config` returns the active (running) configuration; `action=get` would return the
  candidate [PAN-PY `panxapi.py`: "-s show active config at xpath", "-g get candidate config at xpath"].
- Responses: `<response status="success|error">`, with the payload under `<result>` [PAN-PY `__set_xml_response`].
  DOC GAP: the meaning of the `code` attribute (403 read as a refused key) is as remembered.
- Role: an administrator with a read-only role and XML API access (as remembered; confirm with a design partner).

Masked: the text of every leaf element named `phash`, `password`, `secret`, `key`, `private-key`, `community`,
`authpwd`, `privpwd` and similar, or ending in `-password`, `-secret`, `-key`.

## Cisco IOS and IOS-XE (SSH)

- Session set-up as Netmiko does it for `cisco_ios`: `terminal width 511`, then `terminal length 0` [NETMIKO].
- Commands: `show version`, `show running-config`, `show ip arp`, `show mac address-table`. Output layouts follow the
  [NTC] templates `cisco_ios_show_version`, `cisco_ios_show_ip_arp` and `cisco_ios_show_mac-address-table` (four
  layouts; the parser finds the dotted MAC address and the `dynamic` type in any of them).
- `show ip arp` age `-` marks the device's own interface addresses; they are left out.
- Privilege: the account must land at the `#` prompt. Sutra never sends `enable`, so an account that lands at `>`
  is refused with a message saying so.
- Host keys are pinned with the OpenSSH SHA-256 fingerprint (`ssh-keygen -l` form, paramiko's `PKey.fingerprint`):
  the first key seen is recorded, and a different key later stops collection.

Masked in the running configuration: `secret` and `password` values (keeping the encryption type digit), SNMP
community strings, key-strings, OSPF and NTP authentication keys, TACACS+ and RADIUS keys, ISAKMP keys,
pre-shared keys and WPA PSKs.

## Masking

Every masked value is replaced with `SUTRA-MASKED`, keeping the setting's name (and on IOS the encryption type
digit), so a reviewer can see that a secret is set and when it changed without seeing it.

## Change detection

A configuration counts as changed when its SHA-256, taken without the lines a device rewrites by itself, differs from
the last one stored: on IOS `! Last configuration change`, `! NVRAM config last updated`, `ntp clock-period`,
`Building configuration` and `Current configuration : N bytes`; on FortiOS the `#` header lines.

## Not covered yet

- Routes (the product map lists them with ARP and MAC tables).
- FortiGate and PAN-OS ARP tables: their response fields could not be checked against a source.
- Other vendors (Juniper, Arista, Check Point, Cisco ASA and NX-OS).
