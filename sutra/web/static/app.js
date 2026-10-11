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
  buildPersonas();
  const sel = document.getElementById("dataset");
  sel.innerHTML = '<option value="">Switch demo…</option>' +
    Object.entries(STATE.profiles).map(([k, v]) => `<option value="${esc(k)}">${esc(v)}</option>`).join("");
}

// ---------- personas, ownership and scope ----------
// Demo sign-in: pick who you are. A real deployment uses SSO and the same scoping rules on the server.
let PERSONAS = [];
let ME = null;
const teamInfo = (t) => (STATE.org && STATE.org.teams[t]) || { team: t, jira: "", manager: "", vertical: "Unassigned", vertical_head: "" };
function buildPersonas() {
  const sel = document.getElementById("persona");
  PERSONAS = [{ id: "all", kind: "all", name: "Security leadership", label: "Security leadership (all)" }];
  if (STATE.org) {
    const teams = Object.values(STATE.org.teams).filter((t) => !t.team.startsWith("(") && D && Object.values(D.assets).some((a) => assetTeam(a) === t.team));
    PERSONAS.push({ id: "analyst", kind: "analyst", name: STATE.org.vm_analyst, label: STATE.org.vm_analyst });
    const heads = [...new Map(teams.filter((t) => t.vertical_head).map((t) => [t.vertical_head, t.vertical])).entries()];
    heads.forEach(([h, v]) => PERSONAS.push({ id: "head:" + h, kind: "head", name: h, vertical: v, label: `${h} · ${v}` }));
    teams.filter((t) => t.manager).forEach((t) => PERSONAS.push({ id: "mgr:" + t.team, kind: "manager", name: t.manager, team: t.team, label: `${t.manager} · manager, ${t.team}` }));
    teams.forEach((t) => PERSONAS.push({ id: "team:" + t.team, kind: "team", name: `${t.team} team`, team: t.team, label: `${t.team} team` }));
  }
  let saved = ME && ME.id;
  try { saved = saved || localStorage.getItem("sutra.persona"); } catch (e) { /* storage may be blocked */ }
  ME = PERSONAS.find((p) => p.id === saved) || PERSONAS[0];
  sel.innerHTML = PERSONAS.map((p) => `<option value="${esc(p.id)}" ${p.id === ME.id ? "selected" : ""}>${esc(p.label)}</option>`).join("");
  updateInbox();
}
function setPersona(id) {
  ME = PERSONAS.find((p) => p.id === id) || PERSONAS[0];
  try { localStorage.setItem("sutra.persona", ME.id); } catch (e) { /* ignore */ }
  document.getElementById("persona").value = ME.id;
  updateInbox();
}
const assetTeam = (a) => a.owner || "(no owner)";
function inScope(a) {
  if (!ME || ME.kind === "all" || ME.kind === "analyst") return true;
  if (ME.kind === "head") return teamInfo(assetTeam(a)).vertical === ME.vertical;
  return assetTeam(a) === ME.team;
}
const jobInScope = (j) => !ME || ME.kind === "all" || ME.kind === "analyst" ||
  (ME.kind === "head" ? teamInfo(j.team).vertical === ME.vertical : j.team === ME.team);
const waitingOnMe = (j) => j.status === "pending" && j.steps.some((s) => s.state === "current" && s.who === ME.name);
function updateInbox() {
  const n = (STATE.jobs || []).filter(waitingOnMe).length;
  const el = document.getElementById("inbox");
  el.hidden = !n; el.textContent = n;
}
const STATUS_LABEL = { pending: "Awaiting approval", approved: "Approved", rejected: "Rejected", "sent-back": "Sent back", "fixing-manually": "Fixing manually" };
function jobStatus(j) {
  if (j.status === "pending") { const s = j.steps.find((x) => x.state === "current"); return `<span class="status st-pending">Waiting: ${esc(s.label)}</span>`; }
  if (j.status === "approved") return `<span class="status st-approved">${j.is_ot ? "Approved: staged for shutdown" : "Approved: ready to run in rings"}</span>`;
  return `<span class="status st-${esc(j.status)}">${esc(STATUS_LABEL[j.status] || j.status)}</span>`;
}
const jobsFor = (rcId, team) => (STATE.jobs || []).filter((j) => j.rc_id === rcId && (!team || j.team === team));
async function raiseJob(rcId, team, mode) {
  let ticket = "";
  if (mode === "manual") {
    ticket = prompt("Change ticket for the manual fix (for example CHG0012345). Closure still needs a rescan.") ;
    if (ticket === null) return;
  }
  const job = await api("/api/jobs", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ rc_id: rcId, team, mode, ticket, actor: ME.kind === "team" || ME.kind === "manager" ? `${team} team` : ME.name }) });
  await refresh();
  location.hash = `#/job/${job.id}`;
}
function jobTable(jobs) {
  if (!jobs.length) return '<p class="muted">No jobs yet.</p>';
  return `<div class="table-wrap"><table><thead><tr><th>Job</th><th>Root cause</th><th>Team</th><th>Type</th><th>SSVC</th><th>Status</th><th>Jira</th></tr></thead>
    <tbody>${jobs.map((j) => `<tr class="click" data-job="${esc(j.id)}"><td class="id"><b>${esc(j.id)}</b></td>
      <td><div class="t">${esc(j.rc_title)}</div><div class="fix">${j.hosts.length} hosts · ${j.findings.length} findings</div></td>
      <td>${esc(j.team)}</td><td>${j.mode === "manual" ? "Manual fix" : j.is_ot ? "Staged plan" : "Patch job"}${j.route && j.route.emergency ? ' <span class="badge warn">emergency</span>' : ""}</td>
      <td>${ssvc(j.ssvc)}</td><td>${jobStatus(j)}</td><td class="mono">${esc(j.jira)}</td></tr>`).join("")}</tbody></table></div>`;
}
function wireJobRows(root) {
  root.querySelectorAll("tr[data-job]").forEach((tr) => tr.addEventListener("click", () => (location.hash = `#/job/${tr.dataset.job}`)));
}
function myTeamActions(r) {
  if (!ME || (ME.kind !== "team" && ME.kind !== "manager")) return "";
  const mine = r.asset_ids.filter((a) => assetTeam(asset(a)) === ME.team).length;
  if (!mine) return "";
  const open = jobsFor(r.id, ME.team).find((j) => ["pending", "approved", "fixing-manually"].includes(j.status));
  if (open) return `<a href="#/job/${esc(open.id)}">${esc(open.id)}</a> ${jobStatus(open)}`;
  return `<button class="btn primary" data-raise="${esc(r.id)}" data-mode="patch">${r.is_ot ? "Draft staged plan" : "Build patch job"}</button>
    <button class="btn" data-raise="${esc(r.id)}" data-mode="manual">Fixing it myself</button>`;
}
function wireRaise(root) {
  root.querySelectorAll("[data-raise]").forEach((b) => b.addEventListener("click", async (e) => {
    e.stopPropagation(); b.disabled = true;
    try { await raiseJob(b.dataset.raise, ME.team, b.dataset.mode); } catch (err) { alert(err.message); b.disabled = false; }
  }));
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
      <div class="card mt"><div class="toolbar" style="justify-content:space-between;margin:0"><h2 style="margin:0">Patch jobs</h2><div>${myTeamActions(r)}</div></div>
        ${jobsFor(r.id).length ? jobTable(jobsFor(r.id)) : `<p class="muted" style="margin-bottom:0">No jobs yet. Owning teams: ${esc(r.owners.join(", ") || "none mapped")}. Sign in as one of them to build a job.</p>`}</div>
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

  portal() {
    if (!D) return emptyState();
    if (ME.kind === "team" || ME.kind === "manager") {
      const t = teamInfo(ME.team);
      const mine = Object.values(D.assets).filter((a) => assetTeam(a) === ME.team);
      const ids = new Set(mine.map((a) => a.id));
      const rcs = D.root_causes.filter((r) => r.asset_ids.some((a) => ids.has(a)));
      const findings = Object.values(D.findings).filter((f) => ids.has(f.asset_id)).length;
      const risk = rcs.reduce((s, r) => s + r.ale * (r.asset_ids.filter((a) => ids.has(a)).length / r.hosts), 0);
      return `
        <h1>${esc(ME.team)}</h1>
        <p class="sub">Jira project <b class="mono">${esc(t.jira || "–")}</b> · manager ${esc(t.manager || "–")} · ${esc(t.vertical)}${t.vertical_head ? `, headed by ${esc(t.vertical_head)}` : ""}. You see only the assets your team owns.</p>
        <div class="grid kpis">
          <div class="card kpi"><div class="label">Your assets</div><div class="value">${mine.length}</div></div>
          <div class="card kpi"><div class="label">Open findings</div><div class="value">${num(findings)}</div></div>
          <div class="card kpi"><div class="label">Fixes to make</div><div class="value">${rcs.length}</div></div>
          <div class="card kpi"><div class="label">Your share of ₹ risk</div><div class="value">${esc(inr(risk))}</div><div class="note">per year</div></div>
        </div>
        <div class="card"><h2>Your fixes, biggest risk first</h2>
          <p class="muted" style="margin-top:0">Build a patch job and Sutra drafts it and routes it for approval by criticality, or fix it yourself and attach the change ticket. Either way, a rescan closes it.</p>
          <div class="table-wrap"><table><thead><tr><th>Root cause</th><th class="n">Your hosts</th><th>SSVC</th><th class="n">₹ risk / yr</th><th>Due</th><th>Action</th></tr></thead>
          <tbody>${rcs.map((r) => `<tr class="click" data-rc="${esc(r.id)}"><td><div class="t">${esc(r.title)} ${r.is_ot ? otBadge(true) : ""}</div><div class="fix">${esc(r.fix)}</div></td>
            <td class="n">${r.asset_ids.filter((a) => ids.has(a)).length}</td><td>${ssvc(r.ssvc)}</td><td class="n">${esc(r.ale_label)}</td>
            <td>${dueLabel(r.earliest_due)}</td><td style="white-space:nowrap">${myTeamActions(r)}</td></tr>`).join("")}</tbody></table></div></div>
        <div class="card mt"><h2>Your team's jobs</h2>${jobTable((STATE.jobs || []).filter((j) => j.team === ME.team))}</div>`;
    }
    const teams = {};
    D.owners.forEach((o) => (teams[o.owner] = o));
    const visible = D.owners.filter((o) => Object.values(D.assets).some((a) => assetTeam(a) === o.owner && inScope(a)));
    return `
      <h1>Team portal</h1>
      <p class="sub">Every asset maps to a team, a manager and a Jira project. Each team signs in and sees only its own assets. Open a team to see its portal.</p>
      <div class="grid two">${visible.map((o) => { const t = teamInfo(o.owner); return `
        <div class="card"><div class="owner-head"><h2>${esc(o.owner)}</h2><span class="muted">${esc(inr(o.ale))} / yr</span></div>
          <div class="muted" style="font-size:13px;margin:-4px 0 8px">${t.jira ? `Jira ${esc(t.jira)} · ` : ""}${esc(t.manager || "no manager mapped")} · ${esc(t.vertical)}</div>
          ${o.tasks.slice(0, 3).map((x) => `<div class="task"><div>${ssvc(x.ssvc)} <a href="#/rc/${esc(x.id)}"><b>${esc(x.title)}</b></a> ${x.is_ot ? otBadge(true) : ""}</div>
            <div style="font-size:13px">${x.my_hosts} hosts · ${esc(x.ale_label)} / yr · due ${dueLabel(x.earliest_due)}</div></div>`).join("")}
          ${o.tasks.length > 3 ? `<div class="muted" style="font-size:13px">+ ${o.tasks.length - 3} more</div>` : ""}
          <div style="margin-top:10px"><button class="btn" data-as-team="${esc(o.owner)}">Open as this team</button></div>
        </div>`; }).join("")}</div>`;
  },

  jobs() {
    if (!D) return emptyState();
    const jobs = (STATE.jobs || []).filter(jobInScope);
    const mine = (STATE.jobs || []).filter(waitingOnMe);
    return `
      <h1>Patch jobs and approvals</h1>
      <p class="sub">Who approves depends on fixed rules: SSVC category, asset criticality and whether the asset is OT. A drafted job cannot lower its own approval level.</p>
      <div class="card"><h2>Waiting for you${ME.kind === "all" ? "" : `, ${esc(ME.name)}`}</h2>
        ${ME.kind === "all" ? '<p class="muted" style="margin:0">Sign in as a manager, the VM analyst or a vertical head (top right) to approve.</p>' : jobTable(mine)}</div>
      <div class="card mt"><h2>All jobs${ME.kind === "head" ? ` in ${esc(ME.vertical)}` : ME.team ? ` for ${esc(ME.team)}` : ""}</h2>${jobTable(jobs)}</div>
      <div class="card mt"><h2>Approval chain</h2><div class="table-wrap"><table>
        <thead><tr><th>Job type</th><th>Team</th><th>Manager</th><th>VM analyst</th><th>Vertical head</th></tr></thead><tbody>
        <tr><td>Track, non-critical IT asset</td><td>Raises job</td><td>Approves</td><td>Approves</td><td class="muted">Not needed</td></tr>
        <tr><td>Attend or Track*, or a crown-jewel IT asset</td><td>Raises job</td><td>Approves</td><td>Approves</td><td>Approves</td></tr>
        <tr><td>Act (actively exploited)</td><td>Raises job</td><td>Approves</td><td>Approves</td><td>Approves; can fast-track as an emergency change</td></tr>
        <tr><td>Any OT asset</td><td>Raises a staged plan</td><td>Approves</td><td>Approves</td><td>Approves, plus OEM approval and a shutdown slot</td></tr>
        </tbody></table></div></div>`;
  },

  job(id) {
    if (!D) return emptyState();
    const j = (STATE.jobs || []).find((x) => x.id === id);
    if (!j) return `<div class="error">No job ${esc(id)}.</div>`;
    const d = j.draft;
    const cur = j.steps.find((s) => s.state === "current");
    const canAct = j.status === "pending" && cur && cur.who === ME.name;
    const stepState = { waiting: "Waiting", current: "Needs decision", approved: "Approved", rejected: "Rejected", "sent-back": "Sent back" };
    return `
      <div class="crumb"><a href="#/jobs">← Patch jobs</a></div>
      <h1>${esc(j.id)}: ${esc(j.rc_title)}</h1>
      <div class="chips">${jobStatus(j)} ${ssvc(j.ssvc)} ${otBadge(j.is_ot)} <span class="badge">${esc(j.team)}</span>
        <span class="badge mono">Jira ${esc(j.jira)}</span> <a class="badge" href="#/rc/${esc(j.rc_id)}">${esc(j.rc_id)}</a>
        ${j.route && j.route.emergency ? '<span class="badge warn">Emergency change allowed</span>' : ""}</div>
      ${j.route ? `<div class="card"><h2>Approval route</h2><p class="muted" style="margin-top:0">${esc(j.route.reason)}.</p>
        <div class="route"><div class="step approved"><div class="role">Team</div><div class="who">${esc(j.team)}</div><div class="st">Raised</div></div>
        ${j.steps.map((s) => `<div class="step ${esc(s.state)}"><div class="role">${esc(s.label)}</div><div class="who">${esc(s.who)}</div>
          <div class="st">${esc(stepState[s.state])}</div>${s.comment ? `<div class="note-demo">“${esc(s.comment)}”</div>` : ""}</div>`).join("")}
        ${j.is_ot ? `<div class="step ${j.status === "approved" ? "current" : "waiting"}"><div class="role">Plant</div><div class="who">Plant engineer</div><div class="st">${j.status === "approved" ? "Executes at shutdown" : "After approval"}</div></div>` : ""}</div>
        ${canAct ? `<div style="margin-top:12px"><textarea id="comment" placeholder="Comment (optional)"></textarea>
          <div class="toolbar" style="margin-top:8px"><button class="btn primary" data-act="approve">Approve${j.route.emergency && cur.role === "vertical_head" ? " as emergency change" : ""}</button>
          <button class="btn" data-act="sendback">Send back</button><button class="btn" data-act="reject">Reject</button></div></div>` :
          cur ? `<p class="muted" style="margin-bottom:0">Waiting for ${esc(cur.who)}. Sign in as them (top right) to decide.</p>` : ""}
        </div>` : `<div class="card"><h2>Manual fix</h2><p style="margin:0">The team is fixing this by hand${j.ticket ? ` under change ticket <b class="mono">${esc(j.ticket)}</b>` : ""}. The findings close only when a rescan proves the fix.</p></div>`}
      ${d ? `<div class="grid two" style="margin-top:14px">
        <div class="card"><h2>${j.is_ot ? "Staged plan" : "Patch job"} drafted by Sutra</h2>
          <p style="margin-top:0">${esc(d.summary)}</p>
          <dl class="kv"><dt>Tool</dt><dd>${esc(d.tool)}</dd><dt>Window</dt><dd>${esc(d.window)}</dd>
          <dt>Changes</dt><dd>${d.changes.map(esc).join("<br>")}</dd>
          ${d.oem_approval ? `<dt>OEM approval</dt><dd><span class="badge warn">${esc(d.oem_approval)}</span></dd><dt>Hold with</dt><dd>${esc(d.compensating_control)}</dd>` : ""}
          <dt>Rings</dt><dd>${d.rings.map((r) => `${esc(r.name)}: ${r.hosts.length} host${r.hosts.length === 1 ? "" : "s"}`).join("<br>")}</dd></dl>
          <p class="note-demo">In this demo the draft comes from templates; the AI drafting step slots in here. Approval routing never depends on the draft.</p></div>
        <div class="card"><h2>Pre-checks and rollback</h2><ul style="margin-top:0">${d.prechecks.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>
          <p><b>Rollback:</b> ${esc(d.rollback)}</p>
          <p class="muted" style="margin-bottom:0">Targets: ${d.targets.map(esc).join(", ")}</p></div></div>
      <div class="card mt"><h2>${j.is_ot ? "Plan steps" : "Playbook"}</h2><pre class="playbook">${esc(d.playbook)}</pre></div>` : ""}
      <div class="card mt"><h2>Audit trail</h2><p class="muted" style="margin-top:0">Kept as CEA evidence.</p><div class="table-wrap"><table>
        <thead><tr><th>When (UTC)</th><th>Who</th><th>What</th><th>Comment</th></tr></thead>
        <tbody>${j.audit.map((a) => `<tr><td class="mono">${esc(a.at.replace("T", " ").replace("+00:00", ""))}</td><td>${esc(a.actor)}</td><td>${esc(a.action)}</td><td>${esc(a.comment)}</td></tr>`).join("")}</tbody></table></div></div>`;
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
          Generated as Qualys CSV, Tenable CSV, two .nessus plant scans, a CMDB and an ownership chart.</p>
          <button class="btn primary" data-demo="${esc(k)}">Load this demo</button></div>`).join("")}</div>
      <div class="card mt"><h2>Your exports</h2>
        <p class="muted" style="margin-top:0">Supported: Qualys VM detection CSV, Tenable.sc or Tenable.io CSV, Nessus <code>.nessus</code> XML, and an asset register CSV
          (columns: <code>asset_id, hostname, ip, site, zone, os, owner, business_process, inr_per_hour, criticality, image, config_template, is_ot, safety_critical, personal_data</code>), and an ownership chart CSV (<code>team, jira_project, manager, vertical, vertical_head, vm_analyst</code>).</p>
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
  portal(root) {
    wireRcRows(root); wireRaise(root); wireJobRows(root);
    root.querySelectorAll("[data-as-team]").forEach((b) => b.addEventListener("click", () => { setPersona("team:" + b.dataset.asTeam); render(); }));
  },
  jobs(root) { wireJobRows(root); },
  job(root) {
    root.querySelectorAll("[data-act]").forEach((b) => b.addEventListener("click", async () => {
      b.disabled = true;
      try {
        const id = location.hash.split("/")[2];
        await api(`/api/jobs/${encodeURIComponent(id)}/decision`, { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action: b.dataset.act, actor: ME.name, comment: root.querySelector("#comment").value }) });
        await refresh(); render();
      } catch (err) { alert(err.message); b.disabled = false; }
    }));
  },
  board(root) {
    wireRcRows(root);
    root.querySelectorAll("[data-go]").forEach((el) => el.addEventListener("click", (e) => { if (e.target.tagName !== "A") location.hash = el.dataset.go; }));
  },
  rc(root) { wireRaise(root); wireJobRows(root); },
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
  document.querySelectorAll(".nav a").forEach((a) => a.classList.toggle("active", a.dataset.view === ({ rc: "queue", job: "jobs" }[key] || key)));
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
document.getElementById("persona").addEventListener("change", (e) => { setPersona(e.target.value); render(); });
window.addEventListener("hashchange", render);
refresh().then(render).catch((e) => (view.innerHTML = `<div class="error">Could not reach the Sutra server: ${esc(e.message)}</div>`));
