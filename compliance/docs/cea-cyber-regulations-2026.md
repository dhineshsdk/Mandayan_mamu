# CEA cyber security rules for the power sector: what operators owe and where Sutra helps

*Researched 11 October 2026. Covers the Central Electricity Authority (Cyber Security in Power Sector) Regulations, 2026.*

## Read this first: how sure we are

- **The gazette PDF could not be read from here.** The official text is at [cea.nic.in, Cyber_Regulations_Notification.pdf](https://cea.nic.in/wp-content/uploads/notification/2026/08/Cyber_Regulations_Notification.pdf), but the CEA site served a login page to this session. Everything below comes from secondary summaries (consultants, vendors, trade press), cross-checked against each other. Where they agree, the point is marked as solid; where they disagree, the conflict is called out.
- **Regulation numbers are not reliable yet.** Sources number the same duty differently (one vendor puts audits in Reg 8, another places vendor duties in Regs 11–12, a third uses chapter numbers only). This note cites chapters and topics, not clause numbers, except for the deferred list, where two independent sources agree.
- **Before any of this goes into sales material, someone should download the gazette PDF in a normal browser and check the five items in [Open questions](#open-questions-to-settle-against-the-gazette).**

## The basics

| Item | What the sources say | Confidence |
| --- | --- | --- |
| Notification | Gazette of India Extraordinary, Part III, Section 4, No. 484, 31 July 2026, under Section 177 of the Electricity Act 2003 ([CCC](https://ccc-consultants.org/cea-cyber-security-regulations-2026/), [Beacon](https://beaconsecurity.io/resources/blog/cea-cyber-security-power-sector-regulations-2026)) | Solid |
| In force | 1 April 2027 ([Power Line](https://powerline.net.in/2026/08/14/cea-notifies-cea-cyber-security-in-power-sector-regulations-2026/)) | Solid |
| Draft history | Draft published 7 October 2025 for objections ([Beacon](https://beaconsecurity.io/resources/blog/cea-cyber-security-power-sector-regulations-2026)) | Single source |
| Who is covered | Generators, captive plants and storage at **50 MW and above**; all transmission and distribution licensees and NLDC/RLDC/SLDCs with **no threshold**; power exchanges and OTC platforms (excluding the OT and vendor chapters); and **vendors** of control-system hardware, firmware and software, directly ([Shieldworkz](https://shieldworkz.com/regulatory-playbooks/the-cea-cyber-security-in-power-sector-regulations-2026), [CCC](https://ccc-consultants.org/cea-cyber-security-regulations-2026/)) | Solid |
| Below 50 MW | Encouraged, not required, to adopt CERT-In's baseline controls for MSMEs ([CCC](https://ccc-consultants.org/cea-cyber-security-regulations-2026/)) | Solid |
| Deferred to later CEA orders | Regs 5(9), 5(24), 5(33), 5(39), 6(2), 6(7): the 24x7 security division, ISO 27001 or equivalent certificate, mandatory training, trusted-source procurement for IT and OT, and hardware OT perimeter devices such as data diodes ([QRC](https://www.qrcsolutionz.com/blog/cea-cyber-security-regulations-2026-compliance-guide), [CCC](https://ccc-consultants.org/cea-cyber-security-regulations-2026/), mapping from [Shieldworkz guide](https://shieldworkz.com/blogs/cea-(cyber-security-in-power-sector)-regulations-2026-practical-compliance-and-implementation-guide)) | Numbers solid; topic mapping from one source |
| Penalties | No fixed fines. The Ministry of Power's CISO can order a third-party audit at the entity's cost and recommend proceedings under the IT Act 2000 or a petition before the electricity regulatory commission ([Beacon](https://beaconsecurity.io/resources/blog/cea-cyber-security-power-sector-regulations-2026)) | Single source |

## Obligations on covered operators

**People and governance**
- A CISO and an alternate CISO: Indian citizens and residents, regular senior-management employees, engineering degree, 15+ years in power or IT, at least a 3-year tenure, reporting to the head of the entity, working on cyber security only, and never both posts vacant at once.
- A cyber security policy covering 33 set topics, approved and reviewed every year by the head or board.
- A Cyber Crisis Management Plan prepared with CSIRT-Power and vetted by CERT-In, tested at least yearly with drills whose scenarios cannot repeat until the whole list has been used.
- An incident response and recovery plan reviewed at least every six months.

**Assets and risk**
- A cyber asset register for IT and OT, plus a record of each critical system's configuration, network architecture, data flows and protocols. Reviewed yearly or whenever an asset is commissioned or replaced.
- Every asset classed critical or non-critical, with a risk assessment and mitigation plan per asset updated **at least every six months**.
- Vulnerability management for critical systems written into the policy.

**OT isolation and access**
- OT physically isolated from the internet and from IT by default. Any unavoidable link needs a risk assessment, head or board approval, hardened logical separation, continuous monitoring and a unidirectional gateway.
- OT split into trust levels by criticality; OT perimeter devices that understand OT protocols, updated offline.
- Remote access only for troubleshooting and emergencies. On critical systems it needs a full risk assessment, continuous monitoring and kept records. Remote *operation* only from inside India with head or board approval.
- An OT time source that is terrestrial or Indian-satellite and independent of the internet.

**Data**
- Sensitive and historical data, including cloud-hosted data, encrypted and stored only in India. Control and real-time data on a dedicated channel inside India.
- Online and offline backups of critical systems, no older than one month, with restoration tested.

**Change and procurement**
- Changes listed in the Second Schedule need a cyber security audit before deployment: core process changes, authentication and privilege changes, third-party integrations, encryption and protocol changes, new interfaces, fixes for previously found critical vulnerabilities, and changes to monitoring and response tools.
- Security requirements written into factory and site acceptance tests and vendor SLAs; vendor NDAs that outlive the contract; background checks for vendor staff touching critical systems.
- VAPT before commissioning any new or replaced critical system, with details to CSIRT-Power within 30 days.

**Incident reporting**
- Report cyber incidents to **CSIRT-Power and CERT-In within 6 hours**.
- Where an incident is concluded to be cyber sabotage of a critical system, report within **24 hours** of that conclusion; one vendor guide expects a root-cause analysis and forensic summary with it ([Shieldworkz guide](https://shieldworkz.com/blogs/cea-(cyber-security-in-power-sector)-regulations-2026-practical-compliance-and-implementation-guide)).
- CSIRT-Power may demand network architecture, asset details, logs and forensic records in its own format.
- No source gives the required fields of a report or a log retention period; the policy must set retention.

Sources for this section: [Beacon](https://beaconsecurity.io/resources/blog/cea-cyber-security-power-sector-regulations-2026), [Shieldworkz playbook](https://shieldworkz.com/regulatory-playbooks/the-cea-cyber-security-in-power-sector-regulations-2026), [QRC](https://www.qrcsolutionz.com/blog/cea-cyber-security-regulations-2026-compliance-guide), [Power Line](https://powerline.net.in/2026/08/14/cea-notifies-cea-cyber-security-in-power-sector-regulations-2026/).

## The audit cycle and the clocks on findings

| Step | Deadline | Sources agree? |
| --- | --- | --- |
| Comprehensive audit of all critical systems | Every financial year, 9–15 months apart | Yes (one source notes the two phrasings may conflict) |
| Auditor | CERT-In empanelled, or one designated by the Ministry of Power | Yes |
| Auditor's report | Within 6 weeks of the audit starting | Yes |
| **Critical and high findings fixed** | **Within 1 month of the report** | Yes, four sources |
| **Medium and low findings fixed** | **Within 3 months of the report** | Yes, four sources |
| Compensating controls | Required on any critical or high finding still open, until the auditor clears it | One source ([Beacon](https://beaconsecurity.io/resources/blog/cea-cyber-security-power-sector-regulations-2026)) |
| Closure report by the auditor | Within 6 months of the audit starting; major findings go to the head or board | Yes |
| Next audit | Must check that earlier findings were closed | One source |
| Self-audit against all the regulations | Yearly; gaps closed before the next year's self-audit | Yes |
| Auditor rotation | Conflicting, see open questions | No |

**What auditors will mostly find.** No source publishes statistics on CEA audit results yet; the rules are new. Industry write-ups name the same recurring gaps, which are the findings operators will most likely have to close inside the clocks above ([Thermax whitepaper](https://www.thermaxglobal.com/themes/thermax/assets/pdf/Thermax-Whitepaper-OT-Cybersecurity-in-the-Power-Sector.pdf), [Shieldworkz guide](https://shieldworkz.com/blogs/cea-(cyber-security-in-power-sector)-regulations-2026-practical-compliance-and-implementation-guide)):

1. Asset register covers IT but not OT; no record of OT data flows and protocols.
2. Flat networks or direct IT-to-OT links, such as an OT historian on the corporate network or SCADA reachable from office PCs.
3. Unpatched or end-of-life controllers, HMIs and engineering workstations that the OEM has not cleared for patching.
4. Shared credentials and uncontrolled vendor remote access.
5. Missing logs and audit trails, so incidents cannot be reconstructed.
6. SCADA syncing to public internet time servers.
7. Vendor contracts with no cyber clauses; audits done by a non-empanelled firm; the CIO doubling as CISO.
8. Incident reporting that takes a day or more instead of six hours.

## Where Sutra helps, and where it doesn't

| Obligation or finding | Sutra feature (from the plan) | Fit |
| --- | --- | --- |
| Close critical/high findings in 1 month, medium/low in 3 | Root-cause engine ("fix this one thing, close N findings") and the **CEA fix clock** on the board view, one clock per finding from the audit report date | **Strong.** This is the wedge the plan already describes |
| Compensating controls on findings that can't be fixed in time | Tracked compensating controls, OEM approval status, fixes scheduled to the next shutdown, "honest clock states" | **Strong.** Matches the regulation's compensating-control rule closely |
| Auditor's closure report within 6 months; next audit checks old findings | Fix-safety loop (closure proven by fresh evidence) and evidence receipts on every number | **Strong.** Gives the auditor dated proof per finding |
| Major findings to the head or board | Board and CISO views, board briefing agent | Strong |
| Yearly self-audit against every regulation | Compliance autopilot with CEA mapped as code (V2) | Good, but V2 in the plan |
| Asset register for IT and OT, data flows and protocols, critical/non-critical class | Unified inventory graph and coverage truth map (V1) | **Strong.** Also fixes the most common finding (OT missing from the register) |
| Risk assessment per asset every six months | Graph with SSVC category and FAIR rupee impact per asset and root cause | Good; needs a per-asset report export in the audit pack |
| OT isolated from IT; any link risk-assessed and monitored | Attack-surface module: live IT-to-OT paths, allowed-but-unused rules (V2) | Good as evidence; Sutra does not enforce isolation |
| Second Schedule changes need a prior audit | Fix planner change requests with rollback plans; could flag which changes fall under the Schedule | Gap worth closing: add a "needs pre-deployment audit" flag |
| 6-hour incident report to CSIRT-Power and CERT-In | Compliance agent drafts incident reports; flight recorder for "what changed before" (Year 2) | **Partial.** Drafting helps, but Sutra is not a detection tool, so the clock starts in the customer's SOC |
| 24-hour sabotage report with root cause | Root-cause engine and flight recorder | Partial, and only once the flight recorder exists |
| Vendor remote access controlled and logged | Third-party access module (V3) | Weak for 2027; V3 in the plan |
| Crisis drills with non-repeating scenarios | War games from the real graph (Year 2) | Partial, later |
| Auditor rotation needs consistent evidence | Auditor edition (Year 2) | Good channel idea |
| CISO appointment, policy text, backups, data localisation of the customer's own data, time sync | None | Out of scope; the audit pack can record evidence that they exist |

**What the rules ask of Sutra itself.** Sutra will sell into covered entities, so: its customer data must be stored and processed in India, which favours the on-prem and air-gapped editions; if an OT-touching component is ever installed in a plant, the vendor chapter applies to Sutra too (signed updates, a software bill of materials per CERT-In guidance, end-of-life dates, and a vulnerability-reporting process that feeds CSIRT-Power); and Sutra's own installs in a plant would count as a third-party integration, which may need a pre-deployment audit under the Second Schedule. Staying read-only and passive on OT, as the plan already says, keeps this light. One vendor guide states that active scanning of live control networks (Levels 0–2) is prohibited ([Shieldworkz guide](https://shieldworkz.com/blogs/cea-(cyber-security-in-power-sector)-regulations-2026-practical-compliance-and-implementation-guide)); that supports Sutra's passive design, but it is not confirmed as regulation text.

## Open questions to settle against the gazette

1. **Auditor rotation.** The plan (citing Global Sources) says no agency may audit more than two years in a row. Beacon says no three consecutive audits by the same agency or personnel; Shieldworkz says rotation after three consecutive engagements. These differ by a year; the plan's line on audit-firm channels should be checked.
2. **Clock start.** Beacon says the 1-month and 3-month clocks run from *submission of the audit report*. The fix clock should be built on that, if the gazette agrees.
3. **Audit interval.** "Every financial year" versus "9 to 15 months apart".
4. **Compensating controls.** Only Beacon reports the rule that open critical/high findings need compensating controls until audit clearance. It underpins Sutra's honest-clock pitch, so confirm the wording.
5. **Incident report content and log retention.** Not given by any source; the gazette or later CSIRT-Power formats may set them.

## Changes this suggests for the startup plan

- The plan's fix-clock paragraph (one month for critical/high, three for medium/low, 6-hour reporting) is consistent with every source found. Add that the clock starts at audit-report submission and that the auditor's closure report is due six months after the audit starts.
- Correct or caveat the "more than two years in a row" auditor-rotation claim.
- Note that transmission, distribution and load-despatch entities are covered with no MW threshold, which widens the market beyond the 50 MW generators the plan's segment table emphasises.
- Add a "Second Schedule pre-deployment audit" flag to fix plans; it is cheap and specific to CEA.

## Sources

- [Central Electricity Authority: notification PDF](https://cea.nic.in/wp-content/uploads/notification/2026/08/Cyber_Regulations_Notification.pdf) (official; not readable from this session)
- [Beacon Security: what each chapter requires](https://beaconsecurity.io/resources/blog/cea-cyber-security-power-sector-regulations-2026)
- [Shieldworkz: regulatory playbook](https://shieldworkz.com/regulatory-playbooks/the-cea-cyber-security-in-power-sector-regulations-2026)
- [Shieldworkz: practical compliance guide](https://shieldworkz.com/blogs/cea-(cyber-security-in-power-sector)-regulations-2026-practical-compliance-and-implementation-guide)
- [QRC Solutionz: compliance guide](https://www.qrcsolutionz.com/blog/cea-cyber-security-regulations-2026-compliance-guide)
- [Consultants Consortium of Chennai: summary](https://ccc-consultants.org/cea-cyber-security-regulations-2026/)
- [Power Line: CEA notifies the regulations](https://powerline.net.in/2026/08/14/cea-notifies-cea-cyber-security-in-power-sector-regulations-2026/)
- [Thermax: OT cybersecurity in the power sector (whitepaper)](https://www.thermaxglobal.com/themes/thermax/assets/pdf/Thermax-Whitepaper-OT-Cybersecurity-in-the-Power-Sector.pdf)
