# Attack surface sample network (SAMPLE DATA)

**These configurations are invented samples, not captured from a real plant.** They are written in each vendor's
documented configuration syntax (FortiOS CLI, PAN-OS XML, Cisco IOS) for a fictional plant, and every address comes from
documentation or private ranges. They exist so that the attack surface module, its tests and the demo have something
realistic to read. Hit counts in `hits/` are invented too.

```
 Internet ── port1 [fw-edge FortiGate] port2 ── IT 10.10.0.0/16 (engineering 10.10.5.0/24)
                                      port3 ── DMZ 10.20.0.0/24 (web 10.20.0.10, historian 10.20.0.20)
                                      port4 ── 10.30.0.0/30 ── eth1/1 [fw-plant PAN-OS] eth1/2 ── 10.40.0.0/30
                                                    ── Gi1/0/1 [sw-ot-core Cisco IOS]
                                                         Vlan51 PLC 10.50.1.0/24, Vlan52 SCADA 10.50.2.0/24
```

`zones.json` is the zone map to load (Internet, IT, DMZ, OT). Planted problems, so the tests can check they are found:

| Where | What |
| --- | --- |
| fw-edge policy 6, fw-plant "Vendor remote support", sw-ot-core `SCADA-OUT 40` | Internet → one SCADA host over RDP: a complete Internet-to-OT path |
| fw-edge policy 5, fw-plant "Temporary commissioning", sw-ot-core `SCADA-OUT 50` | IT `/16` → OT `/16`, any service: a broad IT-to-OT path |
| fw-edge policy 7 | A deny placed after a permit that already covers it: it never takes effect |
| fw-edge policy 8 | A redundant copy of policy 3 |
| fw-edge policy 9 | Disabled |
| `hits/` | The broad IT-to-OT rules and the vendor rule have not been used for more than 90 days |
