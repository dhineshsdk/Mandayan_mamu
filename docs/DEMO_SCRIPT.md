# Demo script (about 20 minutes)

For a CISO, plant head or IT head at a power or manufacturing company. Pick the demo company that matches the room.

## Before the meeting

```
SUTRA_COOKIE_SECURE=0 sutra demo-users --profile power     # or manufacturing; prints one account per role
                                                           # loads two monthly imports (5 Sep and 5 Oct 2026)
SUTRA_COOKIE_SECURE=0 sutra serve
```

Keep the printed accounts to hand: you will sign in as several people. Open http://127.0.0.1:8765 in two browser
windows (one private) so you can be the team and an approver side by side. Everything runs on your laptop, with no
internet needed. Say clearly that the data is synthetic; every screen marks it.

## 1. The problem (1 minute)

"Your scanners give you thousands of findings. Your team can fix maybe a few dozen things a month. And the CEA rules
give you one month for critical and high findings from April 2027."

## 2. Board view (3 minutes)

Sign in as the CISO (`ciso@…`).

- **Expected annual loss** in rupees, with a range. "This is the number your board asks for, and every rupee
  traces back to a scanner row."
- **Work to do**: about 750 scanner rows (power) or 450 (manufacturing) become about 20 fixes. "This is the whole point: fix one thing, close hundreds of
  findings."
- **Top 10 fixes close almost all the rupee risk.**
- **CEA fix clock**: how many findings would already be past the window.
- **Coverage**: 12 assets in the register were never scanned (power), including crown-jewel databases and solar RTUs,
  and the hosts nobody owns are counted too. "We show you what we cannot see. Other tools stay silent about it."
- Click **Open board pack**: one printable page for the board meeting.

## 3. One root cause, end to end (4 minutes)

Click **RC-002** (power) or **RC-001** (manufacturing): the vendor HMI image.

- **The fix**: one image, staged plan with OEM approval and a planned outage. "We never touch OT on our own; a
  person executes, and the compensating control is tracked so the CEA clock stays honest."
- **Why Act**: exploited in the wild (CISA KEV), safety-relevant plant.
- **Rupee risk**: open the inputs. "Every assumption is visible and you can change it."
- **Findings and receipts**: each finding shows the scanner, plugin or QID, file and row. The first-seen date is six
  months back: a .nessus file carries no first-seen date, so Sutra keeps it from the earlier import and the CEA clock
  does not restart with every scan.

## 4. Root-cause queue (2 minutes)

Filter to **OT only**, then search for a CVE. "This is the analyst's day: 20 rows, not 750."
Point out the **base image** rows: dozens of RHEL hosts share one golden image, including build boxes the CMDB never
listed. Sutra matched them to the image by their packages.

## 4b. What changed since last month (2 minutes)

Open **What changed**. It compares the two imports: Log4j was fixed everywhere, a new Chrome flaw arrived on laptops,
and the plant teams have nothing fixed because OT waits for the shutdown. "A finding only counts as fixed when its host
was scanned again and the finding was gone. If the host was not rescanned, we say so instead of calling it fixed."
Click a team for the hosts. The team portal shows the same numbers for that team only.

## 5. Team portal and patch approvals (4 minutes)

- Sign in as the team account for *C&I - Unit 2* (power) or *Plant Engineering - Press* (manufacturing). It has
  only **Team portal** and **Patch jobs**. "The plant team sees only its own assets, with their Jira project and
  manager. Each person gets only the modules their role needs."
- Before the meeting, as the admin, set the thermal plant's next shutdown under **Administration → Maintenance
  windows**; without it the plan honestly says the slot is not set.
- Click **Draft staged plan** on the HMI image. Show the draft: OEM approval request, compensating control, the
  shutdown slot, rollback, and the "Based on" line under each step. "For OT, nothing runs by itself. A plant engineer
  executes it at the shutdown. Every step points back to the scan data it came from."
- Show the route: manager, VM analyst, plant head. "The route comes from fixed rules, so a drafted job can never lower
  its own approval level."
- In the other window, sign in as that team's manager: the **Patch jobs** badge shows one waiting. Approve with a
  comment, then sign in as the VM analyst and the vertical head in turn. Point at the audit trail: "this is your CEA
  evidence." Show that the team account has no Approve button: "whoever raises a job can never approve it."
- Sign in as the plant engineer for the thermal plant and open **OT plans**: record the OEM's approval with its
  reference, the compensating control and the shutdown slot, then what happened at the shutdown. "The job still says
  approved: only the next rescan closes it."
- Sign in as the CISO and open **Scorecards**: each team's backlog, overdue jobs, SLA breaches and time to fix, and the
  same by plant. If you imported the second month, the Log4j job shows as proved fixed.
- For IT, sign in as the *Network Security* team and build the NetScaler job (power): it is Act, so the vertical head
  can approve it as an emergency change.
- Sign in as the admin and open **Audit log**: every sign-in, refusal and approval is there.

## 6. Headline check (2 minutes)

As the VM analyst, click **CVE-2023-4966** (power) or **CVE-2018-13379** (manufacturing). "A CVE is in the news this morning. You know
within seconds whether you are exposed, which hosts, and which fix closes it." Then try **CVE-2024-3400**: not
found, and the page reminds you about the unscanned assets.

## 7. Their data (2 minutes)

As the VM analyst, open **Import data**. "Export from Qualys and Tenable the way you already do, CSV or .nessus, drop them here, and you
see this view for your own estate in minutes. Sutra runs on your own server; the files never leave it." Ask for the 14-day assessment.

## Questions to ask them

- Who approves an OT patch today: OEM, plant head or CISO?
- Which scanner exports can you share, and is there a CMDB with business process and downtime cost?
- What does an hour of downtime cost on your most important line or unit?
