# Demo script (about 15 minutes)

For a CISO, plant head or IT head at a power or manufacturing company. Pick the demo company that matches the room.

## Before the meeting

```
python3 -m sutra serve
```

The browser opens on the power demo. To show the manufacturer instead, use **Switch demo** at the top right.
Everything runs on your laptop, with no internet needed. Say clearly that the data is synthetic.

## 1. The problem (1 minute)

"Your scanners give you thousands of findings. Your team can fix maybe a few dozen things a month. And the CEA rules
give you one month for critical and high findings from April 2027."

## 2. Board view (3 minutes)

- **Expected annual loss** in rupees, with a range. "This is the number your board asks for, and every rupee
  traces back to a scanner row."
- **Work to do**: about 1,000 detections become 19 fixes. "This is the whole point: fix one thing, close hundreds of
  findings."
- **Top 10 fixes close almost all the rupee risk.**
- **CEA fix clock**: how many findings would already be past the window.
- **Coverage**: 12 assets in the register were never scanned, including crown-jewel databases and solar RTUs.
  "We show you what we cannot see. Other tools stay silent about it."
- Click **Open board pack**: one printable page for the board meeting.

## 3. One root cause, end to end (4 minutes)

Click **RC-002** (power) or **RC-001** (manufacturing): the vendor HMI image.

- **The fix**: one image, staged plan with OEM approval and a planned outage. "We never touch OT on our own; a
  person executes, and the compensating control is tracked so the CEA clock stays honest."
- **Why Act**: exploited in the wild (CISA KEV), safety-relevant plant.
- **Rupee risk**: open the inputs. "Every assumption is visible and you can change it."
- **Findings and receipts**: each finding shows the scanner, plugin or QID, file and row. Both plant scans are
  listed, which is how we know the finding has been open for six months.

## 4. Root-cause queue (2 minutes)

Filter to **OT only**, then search for a CVE. "This is the analyst's day: 19 rows, not 600."
Point out the **base image** rows: 46 RHEL hosts share one golden image, including 6 build boxes the CMDB never
listed. Sutra matched them to the image by their packages.

## 5. Owners (1 minute)

"Each team gets its own three tasks with a reason and a due date, so nobody chases owners by email."

## 6. Headline check (2 minutes)

Click **CVE-2023-4966** (power) or **CVE-2018-13379** (manufacturing). "A CVE is in the news this morning. You know
within seconds whether you are exposed, which hosts, and which fix closes it." Then try **CVE-2024-3400**: not
found, and the page reminds you about the unscanned assets.

## 7. Their data (2 minutes)

Open **Import data**. "Export from Qualys and Tenable the way you already do, CSV or .nessus, drop them here, and you
see this view for your own estate in minutes. The files never leave your machine." Ask for the 14-day assessment.

## Questions to ask them

- Who approves an OT patch today: OEM, plant head or CISO?
- Which scanner exports can you share, and is there a CMDB with business process and downtime cost?
- What does an hour of downtime cost on your most important line or unit?
