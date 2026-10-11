"use strict";

// ---------- state and helpers ----------
let STATE = null;   // full /api/state response
let D = null;       // STATE.data: the analysis payload
const view = document.getElementById("view");

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const pct = (x) => `${Math.round(x * 100)}%`;
const num = (n) => Number(n).toLocaleString("en-IN");
const ssvcClass = (s) => "s-" + s.replace("*", "star");
const ssvc = (s) => `<span class="ssvc ${ssvcClass(s)}">${esc(s)}</span>`;
const KIND = { "base-image": "Base image", package: "Package", "config-template": "Config template",
  "shared-credential": "Shared credential", "fleet-config": "Fleet config", fleet: "Fleet", single: "Single" };
const SSVC_ORDER = ["Act", "Attend", "Track*", "Track"];
const SSVC_MEANING = {
  Act: "Actively exploited and threatens safety or operations. Act within hours.",
  Attend: "Needs action faster than the normal cycle.",
  "Track*": "Signs of attacker interest. Watch daily and prepare a control.",
  Track: "No active exploitation. Bundle into the next maintenance window.",
};

function inr(v) {
  if (v >= 1e7) return `₹${(v / 1e7).toFixed(1)} crore`;
  if (v >= 1e5) return `₹${(v / 1e5).toFixed(1)} lakh`;
  return `₹${num(Math.round(v))}`;
}
function fmtDate(iso) {
  if (!iso) return "–";
  const d = new Date(iso + "T00:00:00");
  return d.toLocaleDateString("en-IN", { day: "2-digit", month: "short", year: "numeric" });
}
function dueLabel(iso) {
  if (!iso) return '<span class="muted">unknown</span>';
  const days = Math.round((new Date(iso + "T00:00:00") - new Date(D.as_of + "T00:00:00")) / 864e5);
  if (days < 0) return `<span class="badge warn">${-days} days past</span>`;
  return `${fmtDate(iso)} <span class="muted">(${days} days)</span>`;
}
const rcById = (id) => D.root_causes.find((r) => r.id === id);
const asset = (id) => D.assets[id];
const otBadge = (isOt) => (isOt ? '<span class="badge ot">OT</span>' : '<span class="badge">IT</span>');

async function api(path, opts = {}) {
  const res = await fetch(path, opts);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || res.statusText);
  return body;
}
async function refresh() {
  STATE = await api("/api/state");
  D = STATE.data;
  document.getElementById("org").textContent = D ? D.org || "Uploaded data" : "No data loaded";
  document.getElementById("synthetic").hidden = !(STATE.dataset && STATE.dataset.kind === "demo");
  document.getElementById("asof").textContent = D ? `Data as of ${fmtDate(D.as_of)}` : "";
  const sel = document.getElementById("dataset");
  sel.innerHTML = '<option value="">Switch demo…</option>' +
    Object.entries(STATE.profiles).map(([k, v]) => `<option value="${esc(k)}">${esc(v)}</option>`).join("");
}

function bars(rows, max) {
  max = max || Math.max(...rows.map((r) => r.ale), 1);
  return `<div class="bars">${rows.map((r) => `
    <div class="bar-row"><div class="name" title="${esc(r.name)}">${esc(r.name)}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.max(1, (r.ale / max) * 100).toFixed(1)}%"></div></div>
      <div class="val">${esc(r.label)}</div></div>`).join("")}</div>`;
}

function rcTable(rcs, { compact = false } = {}) {
  return `<div class="table-wrap"><table>
    <thead><tr><th>ID</th><th>Root cause and fix</th><th>Type</th><th class="n">Hosts</th><th class="n">Findings</th>
      <th>SSVC</th><th class="n">₹ risk / yr</th>${compact ? "" : '<th>Next CEA due</th><th>Owner</th>'}</tr></thead>
    <tbody>${rcs.map((r) => `
      <tr class="click" data-rc="${esc(r.id)}">
        <td class="muted id">${esc(r.id)}</td>
        <td><div class="t">${esc(r.title)} ${r.is_ot ? otBadge(true) : ""}</div><div class="fix">${esc(r.fix)}</div></td>
        <td>${esc(KIND[r.kind] || r.kind)}</td>
        <td class="n">${r.hosts}</td><td class="n">${r.findings}</td>
        <td>${ssvc(r.ssvc)}</td><td class="n"><b>${esc(r.ale_label)}</b></td>
        ${compact ? "" : `<td>${dueLabel(r.earliest_due)}</td><td class="muted">${esc(r.owners.slice(0, 2).join(", ") || "Not in CMDB")}${r.owners.length > 2 ? ` +${r.owners.length - 2}` : ""}</td>`}
      </tr>`).join("")}</tbody></table></div>`;
}
function wireRcRows(root) {
  root.querySelectorAll("tr[data-rc]").forEach((tr) => tr.addEventListener("click", () => (location.hash = `#/rc/${tr.dataset.rc}`)));
}

function emptyState() {
  return `<div class="card empty"><h1>No data yet</h1>
    <p class="sub">Load a demo company or import scanner exports to begin.</p>
    <a class="btn primary" href="#/import">Import data</a></div>`;
}

// ---------- views ----------
const VIEWS = {
  board() {
    if (!D) return emptyState();
    const h = D.headline, cov = D.coverage, p = D.portfolio_labels;
    const total = D.root_causes.length || 1;
    const stack = SSVC_ORDER.map((k) => `<div class="${ssvcClass(k)}" style="width:${((h.ssvc[k] || 0) / total) * 100}%" title="${k}: ${h.ssvc[k] || 0}"></div>`).join("");
    const act = D.root_causes.filter((r) => r.ssvc === "Act");
    return `
      <h1>How exposed are we, in rupees?</h1>
      <p class="sub">${esc(num(D.raw_rows))} scanner detections from ${Object.keys(D.sources).length} files, merged and grouped by the one fix that closes them.</p>
      <div class="grid kpis">
        <div class="card kpi"><div class="label">Expected annual loss</div><div class="value">${esc(p.ale_mean)}</div>
          <div class="note">80% range ${esc(p.ale_p10)} to ${esc(p.ale_p90)}</div></div>
        <div class="card kpi link" data-go="#/queue"><div class="label">Work to do</div><div class="value">${h.root_causes} fixes</div>
          <div class="note">${num(D.raw_rows)} detections → ${num(h.findings)} unique findings → ${h.root_causes} root causes</div></div>
        <div class="card kpi"><div class="label">Top ${h.top_n} fixes close</div><div class="value">${pct(h.top_risk_share)} of ₹ risk</div>
          <div class="note">and ${pct(h.top_findings_share)} of all findings</div></div>
        <div class="card kpi"><div class="label">CEA fix clock</div><div class="value">${num(h.cea_overdue)} past window</div>
          <div class="note">1-month (critical, high) or 3-month window, applies from 1 Apr 2027. Top ${h.top_n} clear ${num(h.cea_overdue_closed_by_top)}.</div></div>
      </div>
      <div class="grid two">
        <div class="card"><h2>Triage (CISA SSVC)</h2>
          <div class="stack">${stack}</div>
          <div class="legend">${SSVC_ORDER.map((k) => `<span>${ssvc(k)} ${h.ssvc[k] || 0}</span>`).join("")}</div>
          ${act.length ? `<p style="margin:12px 0 0">Act now: ${act.map((r) => `<a href="#/rc/${esc(r.id)}">${esc(r.id)}</a> ${esc(r.title)}`).join("; ")}.</p>` : ""}
        </div>
        <div class="card kpi link" data-go="#/assets"><h2>Coverage: what we cannot see</h2>
          <div class="grid three" style="gap:8px">
            <div><div class="value">${cov.scanned_assets}</div><div class="note">assets scanned</div></div>
            <div><div class="value" style="color:var(--act)">${cov.unscanned.length}</div><div class="note">registered, never scanned</div></div>
            <div><div class="value" style="color:var(--attend)">${cov.unknown.length}</div><div class="note">found, not in CMDB</div></div>
          </div>
          <div class="note" style="margin-top:8px">Unscanned assets carry risk this figure does not count.</div>
        </div>
      </div>
      <div class="grid two" style="margin-top:14px">
        <div class="card"><h2>Risk by business process</h2>${bars(D.risk_by_process.slice(0, 8))}</div>
        <div class="card"><h2>Risk by site</h2>${bars(D.risk_by_site)}</div>
      </div>
      <div class="card mt">
        <div class="toolbar" style="justify-content:space-between"><h2 style="margin:0">Top ${h.top_n} root causes, ranked by rupee risk</h2>
          <div class="toolbar" style="margin:0"><a class="btn" href="/api/board" target="_blank" rel="noopener">Open board pack (prints to one page)</a>
          <a class="btn" href="/api/download/receipts.json">Receipts</a></div></div>
        ${rcTable(D.root_causes.slice(0, h.top_n), { compact: true })}
      </div>`;
  },

  queue() {
    if (!D) return emptyState();
    const kinds = [...new Set(D.root_causes.map((r) => r.kind))];
    return `
      <h1>Root-cause queue</h1>
      <p class="sub">${D.root_causes.length} fixes instead of ${num(D.headline.findings)} findings. Click a row for the evidence.</p>
      <div class="toolbar">
        <input type="search" id="q" placeholder="Search title, CVE, owner…" style="min-width:240px">
        <select id="f-ssvc"><option value="">All SSVC</option>${SSVC_ORDER.map((k) => `<option>${k}</option>`).join("")}</select>
        <select id="f-kind"><option value="">All types</option>${kinds.map((k) => `<option value="${esc(k)}">${esc(KIND[k] || k)}</option>`).join("")}</select>
        <select id="f-ot"><option value="">IT and OT</option><option value="it">IT only</option><option value="ot">OT only</option></select>
        <a class="btn" href="/api/download/root_causes.csv">Export CSV</a>
      </div>
      <div class="card" id="queue-table"></div>`;
  },

  rc(id) {
    if (!D) return emptyState();
    const r = rcById(id);
    if (!r) return `<div class="error">No root cause ${esc(id)}.</div>`;
    const ri = r.risk_inputs;
    const findings = r.finding_ids.map((f) => D.findings[f]);
    const kev = r.cves.filter((c) => c.exploitation === "active");
    return `
      <div class="crumb"><a href="#/queue">← Root-cause queue</a></div>
      <h1>${esc(r.title)}</h1>
      <div class="chips">${ssvc(r.ssvc)} <span class="badge">${esc(KIND[r.kind] || r.kind)}</span> ${otBadge(r.is_ot)}
        <span class="badge">${esc(r.id)}</span> <span class="badge">max ${esc(r.max_severity)}, CVSS ${r.max_cvss || "–"}</span></div>
      <div class="grid three">
        <div class="card"><h2>The fix</h2><p style="margin:0 0 8px">${esc(r.fix)}</p>
          <p class="muted" style="margin:0">${esc(r.executor)}.</p>
          <p style="margin:10px 0 0">Closes <b>${r.findings}</b> findings on <b>${r.hosts}</b> hosts.</p></div>
        <div class="card"><h2>Why ${esc(r.ssvc)}</h2>
          <dl class="kv"><dt>Exploitation</dt><dd>${esc(r.exploitation)}${kev.length ? ` <span class="badge kev">KEV: ${kev.map((c) => esc(c.name || c.id)).join(", ")}</span>` : ""}</dd>
          <dt>Exposure</dt><dd>${esc(r.exposure)} (most exposed zone: ${esc(ri.top_zone)})</dd>
          <dt>Human impact</dt><dd>${esc(r.human_impact)}</dd></dl>
          <p class="muted" style="margin:10px 0 0">${esc(SSVC_MEANING[r.ssvc])}</p></div>
        <div class="card"><h2>Rupee risk per year</h2><div class="kpi"><div class="value">${esc(r.ale_label)}</div>
          <div class="note">80% range ${esc(inr(r.ale_p10))} to ${esc(inr(r.ale_p90))}</div></div>
          <dl class="kv" style="margin-top:10px"><dt>Attempts / yr</dt><dd>${ri.tef_pert.join(" – ")} (PERT)</dd>
          <dt>Success chance</dt><dd>${pct(ri.vulnerability)}</dd>
          <dt>₹ / hour at stake</dt><dd>${esc(inr(ri.inr_per_hour_at_risk))}</dd>
          <dt>Outage hours</dt><dd>${ri.outage_hours_pert.join(" – ")}</dd>
          <dt>Processes</dt><dd>${esc(ri.processes.join(", "))}</dd></dl></div>
      </div>
      <div class="card mt"><h2>CEA fix clock</h2>
        <p style="margin:0">${r.cea_overdue ? `<b>${r.cea_overdue}</b> of ${r.findings} findings are past their window. ` : "No findings past their window. "}
        Earliest due: ${dueLabel(r.earliest_due)}.${r.is_ot ? " For OT, record the compensating control and the planned outage so the clock reads honestly." : ""}</p></div>
      <div class="card mt"><h2>Hosts (${r.hosts})</h2><div class="table-wrap"><table>
        <thead><tr><th>Host</th><th>IP</th><th>Site</th><th>Zone</th><th>Owner</th><th>Business process</th><th>Image</th></tr></thead>
        <tbody>${r.asset_ids.map((a) => { const x = asset(a); return `<tr><td><b>${esc(x.hostname)}</b>${x.in_cmdb ? "" : ' <span class="badge warn">not in CMDB</span>'}</td>
          <td class="mono">${esc(x.ip)}</td><td>${esc(x.site || "–")}</td><td>${esc(x.zone)}</td><td>${esc(x.owner || "–")}</td>
          <td>${esc(x.process || "–")}</td><td>${esc(x.image || "–")}${x.image_source && x.image_source !== "cmdb" ? ` <span class="muted">${esc(x.image_source)}</span>` : ""}</td></tr>`; }).join("")}</tbody></table></div></div>
      <div class="card mt"><h2>Findings and receipts (${r.findings})</h2>
        <p class="muted" style="margin-top:0">Each finding lists the scanner rows it came from. Rows seen by both scanners were merged.</p>
        <div class="table-wrap"><table>
        <thead><tr><th>Finding</th><th>Host</th><th>Severity</th><th>First seen</th><th>CEA due</th><th>Receipts</th></tr></thead>
        <tbody>${findings.map((f) => `<tr><td><div class="t">${esc(f.title)}</div>
            <div class="fix">${f.package ? `${esc(f.package)} ${esc(f.installed)} → ${esc(f.fixed)}` : esc(f.control || f.credential_fp || "")} ${f.cves.length ? `· ${esc(f.cves.join(", "))}` : ""}</div>
            <details><summary>Evidence</summary><pre class="evidence">${esc(f.evidence)}</pre></details></td>
          <td>${esc(asset(f.asset_id).hostname)}</td><td>${esc(f.severity)}${f.cvss ? ` <span class="muted">${f.cvss}</span>` : ""}</td>
          <td>${fmtDate(f.first_seen)}</td><td>${dueLabel(f.due)}</td>
          <td class="mono" style="font-size:11.5px">${f.sources.map((s) => `${esc(s.scanner)} ${esc(s.scanner_ref)}<br><span class="muted">${esc(s.source_file)}:${esc(s.source_row)}</span>`).join("<br>")}</td></tr>`).join("")}</tbody></table></div></div>`;
  },

  assets() {
    if (!D) return emptyState();
    const cov = D.coverage;
    const counts = {};
    Object.values(D.findings).forEach((f) => (counts[f.asset_id] = (counts[f.asset_id] || 0) + 1));
    const row = (x, extra = "") => `<tr><td><b>${esc(x.hostname)}</b> ${x.is_ot ? otBadge(true) : ""}</td><td class="mono">${esc(x.ip)}</td>
      <td>${esc(x.site || "–")}</td><td>${esc(x.zone)}</td><td>${esc(x.owner || "–")}</td><td class="n">${x.criticality}</td>${extra}</tr>`;
    return `
      <h1>Assets and coverage</h1>
      <p class="sub">Sutra shows what it cannot see. Blind spots are listed before the inventory.</p>
      <div class="grid kpis">
        <div class="card kpi"><div class="label">In the CMDB</div><div class="value">${cov.cmdb_assets}</div></div>
        <div class="card kpi"><div class="label">Scanned</div><div class="value">${cov.scanned_assets}</div><div class="note">${cov.multi_scanner_findings} findings confirmed by both scanners</div></div>
        <div class="card kpi"><div class="label">Never scanned</div><div class="value" style="color:var(--act)">${cov.unscanned.length}</div><div class="note">${cov.unscanned.filter((a) => asset(a).criticality >= 5).length} crown-jewel, ${cov.unscanned.filter((a) => asset(a).is_ot).length} OT</div></div>
        <div class="card kpi"><div class="label">Not in the CMDB</div><div class="value" style="color:var(--attend)">${cov.unknown.length}</div><div class="note">${cov.inferred_images.length} matched to a golden image</div></div>
      </div>
      <div class="grid two">
        <div class="card"><h2>Registered but never scanned</h2><div class="table-wrap"><table>
          <thead><tr><th>Host</th><th>IP</th><th>Site</th><th>Zone</th><th>Owner</th><th class="n">Crit.</th></tr></thead>
          <tbody>${cov.unscanned.map((a) => row(asset(a))).join("") || '<tr><td colspan="6" class="muted">None</td></tr>'}</tbody></table></div></div>
        <div class="card"><h2>Scanned but missing from the CMDB</h2><div class="table-wrap"><table>
          <thead><tr><th>Host</th><th>IP</th><th>OS</th><th>Image match</th><th class="n">Findings</th></tr></thead>
          <tbody>${cov.unknown.map((a) => { const x = asset(a); return `<tr><td><b>${esc(x.hostname)}</b></td><td class="mono">${esc(x.ip)}</td>
            <td>${esc(x.os || "–")}</td><td>${x.image ? `${esc(x.image)} <span class="muted">${esc(x.image_source)}</span>` : '<span class="muted">no match</span>'}</td>
            <td class="n">${counts[a] || 0}</td></tr>`; }).join("") || '<tr><td colspan="5" class="muted">None</td></tr>'}</tbody></table></div></div>
      </div>
      <div class="card mt"><div class="toolbar" style="justify-content:space-between"><h2 style="margin:0">All assets</h2>
        <input type="search" id="aq" placeholder="Search host, IP, owner, image…" style="min-width:240px"></div>
        <div class="table-wrap"><table><thead><tr><th>Host</th><th>IP</th><th>Site</th><th>Zone</th><th>Owner</th><th class="n">Crit.</th><th>Image</th><th>Scanners</th><th class="n">Findings</th></tr></thead>
        <tbody id="asset-rows"></tbody></table></div></div>`;
  },

  owners() {
    if (!D) return emptyState();
    return `
      <h1>Owners: what to do this week</h1>
      <p class="sub">Each team sees its own tasks, biggest rupee risk first, with plain reasons and due dates.</p>
      <div class="grid two">${D.owners.map((o) => `
        <div class="card"><div class="owner-head"><h2>${esc(o.owner)}</h2><span class="muted">${esc(inr(o.ale))} / yr</span></div>
          ${o.tasks.slice(0, 3).map((t) => `<div class="task"><div>${ssvc(t.ssvc)} <a href="#/rc/${esc(t.id)}"><b>${esc(t.title)}</b></a> ${t.is_ot ? otBadge(true) : ""}</div>
            <div class="muted" style="font-size:13px">${esc(t.fix)}</div>
            <div style="font-size:13px">${t.my_hosts} of your hosts · ${esc(t.ale_label)} / yr · due ${dueLabel(t.earliest_due)}</div></div>`).join("")}
          ${o.tasks.length > 3 ? `<div class="muted" style="font-size:13px">+ ${o.tasks.length - 3} more in the queue</div>` : ""}
        </div>`).join("")}</div>`;
  },

  headline() {
    if (!D) return emptyState();
    return `
      <h1>Headline check: are we exposed?</h1>
      <p class="sub">Type a CVE or product from today's news. The answer comes from the latest scans, with the hosts and fixes behind it.</p>
      <form id="hc" class="toolbar"><input type="search" id="hq" placeholder="CVE-2023-4966, log4j, FortiOS…" style="min-width:320px" required>
        <button class="btn primary">Check</button></form>
      <div class="toolbar">${["CVE-2023-4966", "CVE-2018-13379", "CVE-2019-0708", "log4j", "CVE-2024-3400"].map((q) => `<button class="btn" data-q="${q}">${q}</button>`).join("")}</div>
      <div id="hc-out"></div>`;
  },

  import() {
    const prof = STATE.profiles;
    const ups = STATE.uploads;
    return `
      <h1>Import data</h1>
      <p class="sub">Load a demo company, or drop in real exports. Everything stays on this machine.</p>
      <div class="grid two">${Object.entries(prof).map(([k, v]) => `
        <div class="card"><h2>${esc(v)}</h2>
          <p class="muted" style="margin-top:0">${k === "power" ? "Thermal plant with Windows 7 HMIs and Siemens PLCs, HQ IT, NetScaler edge, solar park." : "Press, paint and assembly lines with Rockwell PLCs and FactoryTalk HMIs, MES servers, FortiGate edge."}
          Generated as Qualys CSV, Tenable CSV, two .nessus plant scans and a CMDB.</p>
          <button class="btn primary" data-demo="${esc(k)}">Load this demo</button></div>`).join("")}</div>
      <div class="card mt"><h2>Your exports</h2>
        <p class="muted" style="margin-top:0">Supported: Qualys VM detection CSV, Tenable.sc or Tenable.io CSV, Nessus <code>.nessus</code> XML, and an asset register CSV
          (columns: <code>asset_id, hostname, ip, site, zone, os, owner, business_process, inr_per_hour, criticality, image, config_template, is_ot, safety_critical, personal_data</code>).</p>
        <label class="drop" id="drop" for="file">Drop files here or click to choose<input type="file" id="file" multiple hidden></label>
        <div id="up-list" style="margin-top:12px">${ups.length ? `<table><thead><tr><th>File</th><th>Detected as</th><th class="n">Size</th></tr></thead><tbody>
          ${ups.map((u) => `<tr><td>${esc(u.name)}</td><td><span class="badge">${esc(u.format)}</span></td><td class="n">${num(Math.round(u.bytes / 1024))} KB</td></tr>`).join("")}</tbody></table>` : '<p class="muted">No files uploaded.</p>'}</div>
        <div class="toolbar" style="margin-top:12px"><input type="text" id="org-in" placeholder="Organisation name">
          <button class="btn primary" id="analyze" ${ups.length ? "" : "disabled"}>Analyse uploaded files</button>
          <button class="btn" id="clear" ${ups.length ? "" : "disabled"}>Clear uploads</button></div>
        <div id="imp-msg"></div></div>`;
  },
};

// ---------- interactive wiring after render ----------
const WIRE = {
  board(root) {
    wireRcRows(root);
    root.querySelectorAll("[data-go]").forEach((el) => el.addEventListener("click", (e) => { if (e.target.tagName !== "A") location.hash = el.dataset.go; }));
  },
  queue(root) {
    if (!D) return;
    const draw = () => {
      const q = root.querySelector("#q").value.trim().toLowerCase();
      const s = root.querySelector("#f-ssvc").value, k = root.querySelector("#f-kind").value, ot = root.querySelector("#f-ot").value;
      const rows = D.root_causes.filter((r) => (!s || r.ssvc === s) && (!k || r.kind === k) &&
        (!ot || (ot === "ot") === r.is_ot) &&
        (!q || [r.title, r.fix, r.id, ...r.owners, ...r.cves.map((c) => c.id)].join(" ").toLowerCase().includes(q)));
      const box = root.querySelector("#queue-table");
      box.innerHTML = rows.length ? rcTable(rows) : '<p class="muted">No root causes match.</p>';
      wireRcRows(box);
    };
    root.querySelectorAll("#q, #f-ssvc, #f-kind, #f-ot").forEach((el) => el.addEventListener("input", draw));
    draw();
  },
  assets(root) {
    if (!D) return;
    const counts = {};
    Object.values(D.findings).forEach((f) => (counts[f.asset_id] = (counts[f.asset_id] || 0) + 1));
    const all = Object.values(D.assets).sort((a, b) => b.criticality - a.criticality || a.hostname.localeCompare(b.hostname));
    const draw = () => {
      const q = root.querySelector("#aq").value.trim().toLowerCase();
      const rows = all.filter((x) => !q || [x.hostname, x.ip, x.owner, x.image, x.site, x.os, x.process].join(" ").toLowerCase().includes(q)).slice(0, 400);
      root.querySelector("#asset-rows").innerHTML = rows.map((x) => `<tr><td><b>${esc(x.hostname)}</b> ${x.is_ot ? otBadge(true) : ""}${x.in_cmdb ? "" : ' <span class="badge warn">not in CMDB</span>'}</td>
        <td class="mono">${esc(x.ip)}</td><td>${esc(x.site || "–")}</td><td>${esc(x.zone)}</td><td>${esc(x.owner || "–")}</td><td class="n">${x.criticality}</td>
        <td>${esc(x.image || "–")}</td><td>${x.scanned_by.length ? esc(x.scanned_by.join(", ")) : '<span class="badge warn">none</span>'}</td><td class="n">${counts[x.id] || 0}</td></tr>`).join("");
    };
    root.querySelector("#aq").addEventListener("input", draw);
    draw();
  },
  headline(root) {
    const out = root.querySelector("#hc-out");
    const run = async (q) => {
      root.querySelector("#hq").value = q;
      out.innerHTML = '<p class="muted">Checking…</p>';
      try {
        const r = await api("/api/headline", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ query: q }) });
        const intel = r.intel ? ` <span class="badge kev">${esc(r.intel.exploitation === "active" ? "Known exploited" : "Public exploit")}: ${esc(r.intel.name)}</span>` : "";
        out.innerHTML = `<div class="card">
          <div class="answer ${r.exposed ? "yes" : "no"}">${r.exposed ? `Yes: ${r.hosts} host${r.hosts === 1 ? "" : "s"} exposed` : "Not found on any scanned host"}${intel}</div>
          <p class="muted">${r.exposed ? `${r.findings} findings · ${r.internet_hosts} internet-facing · ${r.ot_hosts} OT.` : ""}
            ${r.unscanned_note ? `${r.unscanned_note} registered assets are never scanned, so they are not covered by this answer.` : ""}</p>
          ${r.exposed ? `<h2>Fixes that close it</h2>${rcTable(r.root_causes.map(rcById), { compact: true })}
          <h2 style="margin-top:14px">Hosts</h2><p>${r.asset_ids.map((a) => `${esc(asset(a).hostname)} <span class="muted mono">${esc(asset(a).ip)}</span>`).join(" · ")}</p>` : ""}</div>`;
        wireRcRows(out);
      } catch (e) { out.innerHTML = `<div class="error">${esc(e.message)}</div>`; }
    };
    root.querySelector("#hc").addEventListener("submit", (e) => { e.preventDefault(); run(root.querySelector("#hq").value); });
    root.querySelectorAll("[data-q]").forEach((b) => b.addEventListener("click", () => run(b.dataset.q)));
  },
  import(root) {
    const msg = root.querySelector("#imp-msg");
    const fail = (e) => (msg.innerHTML = `<div class="error" style="margin-top:10px">${esc(e.message)}</div>`);
    root.querySelectorAll("[data-demo]").forEach((b) => b.addEventListener("click", async () => {
      b.disabled = true; b.textContent = "Loading…";
      try { await api("/api/demo", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ profile: b.dataset.demo }) });
        await refresh(); location.hash = "#/board"; } catch (e) { fail(e); b.disabled = false; b.textContent = "Load this demo"; }
    }));
    const upload = async (files) => {
      msg.innerHTML = '<p class="muted">Uploading…</p>';
      for (const f of files) {
        try { await api(`/api/upload?name=${encodeURIComponent(f.name)}`, { method: "POST", body: f }); }
        catch (e) { return fail(new Error(`${f.name}: ${e.message}`)); }
      }
      await refresh(); render();
    };
    const drop = root.querySelector("#drop");
    root.querySelector("#file").addEventListener("change", (e) => upload([...e.target.files]));
    ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
    ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
    drop.addEventListener("drop", (e) => upload([...e.dataTransfer.files]));
    root.querySelector("#analyze").addEventListener("click", async (e) => {
      e.target.disabled = true; e.target.textContent = "Analysing…";
      try { await api("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ org: root.querySelector("#org-in").value }) });
        await refresh(); location.hash = "#/board"; } catch (err) { fail(err); e.target.disabled = false; e.target.textContent = "Analyse uploaded files"; }
    });
    root.querySelector("#clear").addEventListener("click", async () => { await api("/api/upload", { method: "DELETE" }); await refresh(); render(); });
  },
};

// ---------- router ----------
function render() {
  const [name, arg] = (location.hash.replace(/^#\//, "") || "board").split("/");
  const key = VIEWS[name] ? name : "board";
  document.querySelectorAll(".nav a").forEach((a) => a.classList.toggle("active", a.dataset.view === (key === "rc" ? "queue" : key)));
  view.innerHTML = VIEWS[key](decodeURIComponent(arg || ""));
  (WIRE[key] || (() => {}))(view);
  view.focus({ preventScroll: true });
  window.scrollTo(0, 0);
}

document.getElementById("dataset").addEventListener("change", async (e) => {
  const profile = e.target.value;
  if (!profile) return;
  view.innerHTML = '<div class="loading">Loading demo…</div>';
  try { await api("/api/demo", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ profile }) }); }
  catch (err) { view.innerHTML = `<div class="error">${esc(err.message)}</div>`; return; }
  await refresh();
  location.hash = "#/board";
  render();
});
window.addEventListener("hashchange", render);
refresh().then(render).catch((e) => (view.innerHTML = `<div class="error">Could not reach the Sutra server: ${esc(e.message)}</div>`));
