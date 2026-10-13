# Attack surface (M-ATK)

Shows which networks can reach your plant networks, through which devices and rules, and which rules are broad,
shadowed, disabled or unused. It reads the firewall and switch configurations Sutra already collects (Import data →
network devices); it sends nothing to any device.

## What it does

1. **Parses** the latest stored configuration of each enabled device into a device model: interfaces and addresses,
   connected networks, static routes, and an ordered rule list.
   FortiGate (FortiOS CLI, one device per VDOM), Palo Alto (PAN-OS XML) and Cisco IOS / IOS-XE (standard and
   extended ACLs, named and numbered, applied with `ip access-group`).
2. **Evaluates rules exactly.** Each rule is a set of (source address, destination address, protocol and port)
   boxes; first match wins and everything else is denied. The evaluation is set arithmetic, not sampling, so "any
   service" and "tcp/502 from one host" are both answered precisely.
3. **Finds paths** between zones you define: internet, IT and DMZ into OT, and internet into IT. A path starts on the
   devices attached to the source zone, picks the egress interface from connected networks then the longest static
   route, applies the device's rules (a Cisco switch applies the ingress interface's `in` ACL, then the egress
   interface's `out` ACL), and follows the next hop into the next known device. What survives every hop is the path's
   service set. A next hop outside the known devices is reported as an incomplete path rather than dropped.
4. **Flags rules**: broad permits (wide source with any service, or a wide source into OT), rules that never take
   effect because earlier rules cover them (a *deny* that never fires is rated higher than a harmless duplicate),
   disabled rules, and rules with no hits.
5. **Ranks the cuts**: rules ordered by how many risky paths depend on them. "Only permit on" counts the paths a rule
   alone carries at its hop, so removing it closes them. An unused rule on a path is the safest cut.

Severity of a path: internet → OT starts at critical, IT → OT at medium, DMZ → OT and internet → IT at low; a path
that opens 1,000 or more (protocol, port) pairs gains two levels, and one carrying SSH, Telnet, RDP, SMB, VNC,
NetBIOS or MS-RPC gains one. Well-known industrial ports (Modbus 502, S7 102, DNP3 20000, EtherNet/IP 44818, OPC UA
4840, IEC 104 2404, BACnet 47808) are named in the path text so a reader sees what a path carries.

## Setting up

* **Roles.** CISO and VM analyst see it and can change zones and hit counts (`M-ATK` view and act); nobody else is
  given it by default. An admin can grant it to one person.
* **Zones.** On the page, one per line: `ot | Plant OT | 10.50.0.0/16`. Kinds: `internet`, `it`, `dmz`, `ot`. An
  internet zone with no networks means every public address (everything except private, loopback, link-local, CGNAT
  and multicast space). Without an OT zone there is nothing to look for, and the page says so.
* **Hit counts.** Configurations do not carry them, so "unused" needs the counters read from the device and uploaded
  per device (replacing the previous upload):

  | Format | Output to upload | Notes |
  | --- | --- | --- |
  | `csv` | `rule,hits,last_hit,since` | Any vendor. Times ISO 8601 or Unix seconds. |
  | `panos_xml` | `show rule-hit-count vsys vsys-name vsys1 rule-base security rules all` (XML) | Last hit and counter reset come from the output. |
  | `ios_access_lists` | `show access-lists` | `(N matches)`; IOS keeps no last-hit time, so give the date the counters were last cleared. |
  | `fortios_json` | `GET /api/v2/monitor/firewall/policy` | `policyid`, `hit_count`, `last_used`, `first_used`. |

  A rule is called unused when it has had no hits in at least 90 days of counters, or its last hit is older than 90
  days. With a shorter window it is shown as a note, not a finding. Rule keys: FortiOS policy id, PAN-OS rule name,
  IOS `<ACL name> <sequence>`.

## API

`GET /api/attack` (M-ATK view) returns the whole report. `PUT /api/attack/zones`, `POST /api/attack/hits/{device_id}`
and `DELETE /api/attack/hits/{device_id}` need M-ATK act. Zone and hit-count changes are in the audit log.

## What is checked, and what is not

Tested against real vendor files (the Batfish FortiOS policy test file, Palo Alto's Iron Skillet template) for syntax,
and against an **invented sample network** (`examples/attack-surface`, three devices, planted problems listed in its
README) for paths and findings. The syntax in the sample configurations is written from the vendors' documented CLI and
XML forms and Batfish's fixtures; it has not been run against a live device.

Limits, which the page repeats:

* IPv4 only. IPv6 addresses and rules are left out.
* Routing is connected networks and static routes. OSPF, EIGRP and BGP are not read, so a network reachable only
  by a learned route is missed. When a zone spans several subnets, each part is routed by its first address.
* No NAT, application or user identity (a PAN-OS rule limited to named applications is shown as an unresolved
  service), IPS or UTM profiles, schedules, VRFs or SD-WAN. FQDN, geography and dynamic address objects, and Cisco
  `object-group` references, are not resolved; the rule or the device note says so. A name the parser does not know
  becomes a pseudo-service called `unresolved` so the traffic still shows as allowed.
* The PAN-OS implicit intrazone-allow rule is not modelled; Panorama pre/post rulebases are not merged; only the
  first virtual system is read. FortiOS hit counts are applied to every VDOM of a device.
* A path says what the configuration permits, not what traffic exists. Two further V2 items are not built: observed
  traffic against allowed paths, and external-surface scanning.
* The PAN-OS and FortiOS hit-count field names are as remembered from vendor output, not checked against a vendor
  page (the vendor sites could not be reached from the build environment). Check them against a real device before
  relying on those two uploads; the CSV format has no such dependency.
