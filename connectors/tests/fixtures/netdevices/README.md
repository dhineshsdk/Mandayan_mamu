# Network device fixtures

Real device output and configuration, copied unchanged from open-source projects (checked 2026-10-11):

| File | Source | Licence |
| --- | --- | --- |
| `fortios_firewall_policy.conf` | Batfish, `projects/batfish/src/test/resources/org/batfish/grammar/fortios/testconfigs/firewall_policy` | Apache 2.0 |
| `ios_as1border1.cfg` | Batfish example network, `networks/example/live/configs/as1border1.cfg` | Apache 2.0 |
| `ios_show_version_cat4500.raw` | ntc-templates, `tests/cisco_ios/show_version/cisco_ios_show_version.raw` | Apache 2.0 |
| `ios_show_version_cat3k.raw` | ntc-templates, `tests/cisco_ios/show_version/cisco_ios_show_version1.raw` | Apache 2.0 |
| `ios_show_ip_arp.raw` | ntc-templates, `tests/cisco_ios/show_ip_arp/cisco_ios_show_ip_arp.raw` | Apache 2.0 |
| `ios_show_mac_address_table{2,3,4}.raw` | ntc-templates, `tests/cisco_ios/show_mac-address-table/cisco_ios_show_mac-address-table{2,3,4}.raw` | Apache 2.0 |
| `panos_iron_skillet_full.xml` | Palo Alto Networks Iron Skillet, branch `panos_v10.1`, `templates/panos/full/iron_skillet_panos_full.xml` | MIT |

The Iron Skillet file is Palo Alto Networks' day-one configuration template, so it still has its `{{ }}` and `{% %}`
placeholders; it is a real PAN-OS 10.1 configuration document otherwise.

Stand-ins, written for these tests and not copied from a device:

- `fortigate_status.json`: the FortiOS JSON envelope fields `serial`, `version`, `build` and `status` are as Fortinet's
  `fortiosapi` reads them; the `results` field names (`hostname`, `model_name`, `model_number`) are as remembered.
- `panos_system_info.xml`: the element names `sw-version`, `model` and `serial` are the ones `pan-os-python` reads;
  `hostname` is as remembered. The values are invented.
