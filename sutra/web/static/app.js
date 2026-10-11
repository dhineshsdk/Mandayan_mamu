"use strict";

// Every screen loads its data from an API that checks the signed-in person's module, action and scope on the
// server. The navigation below only mirrors those rights; hiding a link is not what protects the data.

// ---------- state and helpers ----------
let ME = null;        // /api/auth/me
let STATUS = null;    // /api/status
let D = null;         // payload of the current screen
let INBOX = 0;
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
const ROLE_NAME = { team_member: "Team member", team_manager: "Team manager", vm_analyst: "VM analyst",
  vertical_head: "Vertical head", plant_engineer: "Plant engineer", ciso: "CISO", compliance_officer: "Compliance officer",
  executive: "Executive", auditor: "Auditor", admin: "Administrator" };

function inr(v) {
  if (v >= 1e7) return `₹${(v / 1e7).toFixed(1)} crore`;
  if (v >= 1e5) return `₹${(v / 1e5).toFixed(1)} lakh`;
  return `₹${num(Math.round(v))}`;
}
function fmtDate(iso) {
  if (!iso) return "–";
  const d = new Date(iso.length === 10 ? iso + "T00:00:00" : iso);
  return d.toLocaleDateString("en-IN", { day: "2-digit", month: "short", year: "numeric" });
}
const fmtTime = (iso) => (iso ? iso.replace("T", " ") + " UTC" : "–");
function dueLabel(iso) {
  if (!iso) return '<span class="muted">unknown</span>';
  const asOf = (D && D.as_of) || (STATUS && STATUS.as_of);
  const days = Math.round((new Date(iso + "T00:00:00") - new Date(asOf + "T00:00:00")) / 864e5);
  if (days < 0) return `<span class="badge warn">${-days} days past</span>`;
  return `${fmtDate(iso)} <span class="muted">(${days} days)</span>`;
}
const otBadge = (isOt) => (isOt ? '<span class="badge ot">OT</span>' : '<span class="badge">IT</span>');
const can = (module, action = "view") => !!ME && ME.modules.some((m) => m.key === module && m.actions.includes(action));

class ApiError extends Error { constructor(msg, status) { super(msg); this.status = status; } }
async function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  const method = (opts.method || "GET").toUpperCase();
  if (method !== "GET" && ME) headers["X-CSRF-Token"] = ME.csrf_token;
  let body = opts.body;
  if (opts.json !== undefined) { headers["Content-Type"] = "application/json"; body = JSON.stringify(opts.json); }
  const res = await fetch(path, { method, headers, body, credentials: "same-origin" });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && !path.startsWith("/api/auth/login")) { showSignIn(); throw new ApiError("Signed out.", 401); }
  if (!res.ok) throw new ApiError(data.error || res.statusText, res.status);
  return data;
}
const post = (path, json) => api(path, { method: "POST", json });

// ---------- navigation: only the modules this person has ----------
const NAV = [
  { view: "board", label: "Board", module: "M-BRD" },
  { view: "queue", label: "Root causes", module: "M-RC" },
  { view: "assets", label: "Assets and coverage", module: "M-AST" },
  { view: "portal", label: "Team portal", module: "M-TP" },
  { view: "jobs", label: "Patch jobs", module: "M-PJ" },
  { view: "changes", label: "What changed", test: () => can("M-RC") || can("M-TP") || can("M-BRD") },
  { view: "headline", label: "Headline check", module: "M-HC" },
  { view: "import", label: "Import data", module: "M-DAT" },
  { view: "audit", label: "Audit log", test: () => can("M-AUD") || can("M-ADM", "admin") },
  { view: "admin", label: "Administration", test: () => can("M-ADM", "admin") || can("M-ADM", "act") },
];
const allowed = (n) => (n.test ? n.test() : can(n.module));
const OWNER_VIEW = { rc: "queue", job: "jobs" };
function buildNav() {
  const items = NAV.filter(allowed);
  document.getElementById("nav").innerHTML = items.map((n) =>
    `<a href="#/${n.view}" data-view="${n.view}">${esc(n.label)}${n.view === "jobs" ? ' <span id="inbox" class="count" hidden></span>' : ""}</a>`).join("") ||
    '<p class="muted" style="padding:0 10px">No modules are switched on for you yet. Ask an administrator.</p>';
  const u = ME.user;
  document.getElementById("who").textContent = u.name;
  document.getElementById("me-foot").innerHTML = ME.roles.map((r) => `${esc(ROLE_NAME[r.role] || r.role)}<br><span>${esc(r.scope)}</span>`).join("<br>") || "No role";
}
function homeView() { const n = NAV.find(allowed); return n ? n.view : "account"; }
async function refreshInbox() {
  if (!can("M-PJ", "approve")) return;
  try { INBOX = (await api("/api/jobs")).waiting_for_me.length; } catch (e) { INBOX = 0; }
  const el = document.getElementById("inbox");
  if (el) { el.hidden = !INBOX; el.textContent = INBOX; }
}
async function refreshStatus() {
  STATUS = await api("/api/status");
  document.getElementById("org").textContent = STATUS.loaded ? STATUS.org || "Uploaded data" : "No data loaded";
  document.getElementById("synthetic").hidden = !STATUS.synthetic;
  document.getElementById("asof").textContent = STATUS.loaded ? `Data as of ${fmtDate(STATUS.as_of)}` : "";
}

// ---------- sign in ----------
async function showSignIn(message) {
  ME = null;
  document.getElementById("shell").hidden = true;
  const box = document.getElementById("signin");
  box.hidden = false;
  let cfg = { local: true, oidc: false };
  try { cfg = await (await fetch("/api/auth/config")).json(); } catch (e) { /* show the form anyway */ }
  const qs = new URLSearchParams((location.hash.split("?")[1]) || "");
  const err = message || { sso: "Single sign-on did not complete. Try again.",
    "no-account": "Your single sign-on account has no Sutra access. Ask an administrator to add you." }[qs.get("error")] || "";
  box.innerHTML = `<div class="card signin-card">
      <div class="brand"><span class="logo"></span>Sutra</div>
      <h1>Sign in</h1>
      ${err ? `<div class="error">${esc(err)}</div>` : ""}
      ${cfg.oidc ? `<a class="btn primary wide" href="/api/auth/oidc/login">${esc(cfg.oidc_label)}</a>` : ""}
      ${cfg.oidc && cfg.local ? '<div class="or">or</div>' : ""}
      ${cfg.local ? `<form id="login-form" class="stack-form">
        <label>Email<input type="email" id="li-email" autocomplete="username" required></label>
        <label>Password<input type="password" id="li-pw" autocomplete="current-password" required></label>
        <button class="btn primary wide">Sign in</button></form>` : ""}
    </div>`;
  const form = document.getElementById("login-form");
  if (form) form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = form.querySelector("button"); btn.disabled = true;
    try {
      ME = await post("/api/auth/login", { email: form.querySelector("#li-email").value, password: form.querySelector("#li-pw").value });
      if (location.hash.startsWith("#/login")) location.hash = "";
      await start();
    } catch (err2) { showSignIn(err2.message); }
  });
}
document.getElementById("signout").addEventListener("click", async () => {
  try { await post("/api/auth/logout", {}); } catch (e) { /* already signed out */ }
  location.hash = "";
  showSignIn("You are signed out.");
});

// ---------- shared pieces ----------
function bars(rows, max) {
  max = max || Math.max(...rows.map((r) => r.ale), 1);
  return `<div class="bars">${rows.map((r) => `
    <div class="bar-row"><div class="name" title="${esc(r.name)}">${esc(r.name)}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.max(1, (r.ale / max) * 100).toFixed(1)}%"></div></div>
      <div class="val">${esc(r.label)}</div></div>`).join("")}</div>`;
}
function rcTable(rcs, { compact = false, link = can("M-RC") } = {}) {
  return `<div class="table-wrap"><table>
    <thead><tr><th>ID</th><th>Root cause and fix</th><th>Type</th><th class="n">Hosts</th><th class="n">Findings</th>
      <th>SSVC</th><th class="n">₹ risk / yr</th>${compact ? "" : "<th>Next CEA due</th><th>Owner</th>"}</tr></thead>
    <tbody>${rcs.map((r) => `
      <tr ${link ? `class="click" data-rc="${esc(r.id)}"` : ""}>
        <td class="muted id">${esc(r.id)}</td>
        <td><div class="t">${esc(r.title)} ${r.is_ot ? otBadge(true) : ""}</div><div class="fix">${esc(r.fix)}</div></td>
        <td>${esc(KIND[r.kind] || r.kind)}</td>
        <td class="n">${r.hosts}</td><td class="n">${r.findings}</td>
        <td>${ssvc(r.ssvc)}</td><td class="n"><b>${esc(r.ale_label)}</b></td>
        ${compact ? "" : `<td>${dueLabel(r.earliest_due)}</td><td class="muted">${esc(r.owners.slice(0, 2).join(", ") || "Not in CMDB")}${r.owners.length > 2 ? ` +${r.owners.length - 2}` : ""}</td>`}
      </tr>`).join("")}</tbody></table></div>`;
}
function wireRows(root) {
  root.querySelectorAll("tr[data-rc]").forEach((tr) => tr.addEventListener("click", () => (location.hash = `#/rc/${tr.dataset.rc}`)));
  root.querySelectorAll("tr[data-job]").forEach((tr) => tr.addEventListener("click", () => (location.hash = `#/job/${tr.dataset.job}`)));
}
function emptyState() {
  return `<div class="card empty"><h1>No data yet</h1>
    <p class="sub">${can("M-DAT", "act") ? "Load a demo company or import scanner exports to begin." : "An analyst has not imported any scan data yet."}</p>
    ${can("M-DAT", "act") ? '<a class="btn primary" href="#/import">Import data</a>' : ""}</div>`;
}
const STATUS_LABEL = { drafting: "Drafting", "draft-failed": "Draft failed", pending: "Awaiting approval", approved: "Approved", rejected: "Rejected", "sent-back": "Sent back", "fixing-manually": "Fixing manually" };
function jobStatus(j) {
  if (j.status === "pending") { const s = j.steps.find((x) => x.state === "current"); return `<span class="status st-pending">Waiting: ${esc(s.label)}</span>`; }
  if (j.status === "approved") return `<span class="status st-approved">${j.is_ot ? "Approved: staged for shutdown" : "Approved: ready to run in rings"}</span>`;
  return `<span class="status st-${esc(j.status)}">${esc(STATUS_LABEL[j.status] || j.status)}</span>`;
}
function jobTable(jobs) {
  if (!jobs.length) return '<p class="muted">No jobs.</p>';
  return `<div class="table-wrap"><table><thead><tr><th>Job</th><th>Root cause</th><th>Team</th><th>Type</th><th>SSVC</th><th>Status</th><th>Jira</th></tr></thead>
    <tbody>${jobs.map((j) => `<tr class="click" data-job="${j.pk}"><td class="id"><b>${esc(j.id)}</b></td>
      <td><div class="t">${esc(j.rc_title)}</div><div class="fix">${j.hosts.length} hosts · ${j.findings.length} findings</div></td>
      <td>${esc(j.team)}</td><td>${j.mode === "manual" ? "Manual fix" : j.is_ot ? "Staged plan" : "Patch job"}${j.route && j.route.emergency ? ' <span class="badge warn">emergency</span>' : ""}</td>
      <td>${ssvc(j.ssvc)}</td><td>${jobStatus(j)}</td><td class="mono">${esc(j.jira)}</td></tr>`).join("")}</tbody></table></div>`;
}
const OPEN = ["drafting", "pending", "approved", "fixing-manually"];
// Buttons to raise a job, for each team this person may raise jobs for that owns hosts in this root cause.
function raiseButtons(rc, teams, jobs) {
  return teams.map((team) => {
    const open = jobs.find((j) => j.rc_current_id === rc.id && j.team === team && OPEN.includes(j.status));
    if (open) return `<div><a href="#/job/${open.pk}">${esc(open.id)}</a> ${jobStatus(open)}${teams.length > 1 ? ` <span class="muted">${esc(team)}</span>` : ""}</div>`;
    return `<div class="toolbar" style="margin:0 0 4px">${teams.length > 1 ? `<span class="muted">${esc(team)}:</span>` : ""}
      <button class="btn small primary" data-raise="${esc(rc.id)}" data-team="${esc(team)}" data-mode="patch">${rc.is_ot ? "Draft staged plan" : "Build patch job"}</button>
      <button class="btn small" data-raise="${esc(rc.id)}" data-team="${esc(team)}" data-mode="manual">Fixing it myself</button></div>`;
  }).join("");
}
function wireRaise(root) {
  root.querySelectorAll("[data-raise]").forEach((b) => b.addEventListener("click", async (e) => {
    e.stopPropagation();
    let ticket = "";
    if (b.dataset.mode === "manual") {
      ticket = prompt("Change ticket for the manual fix (for example CHG0012345). Closure still needs a rescan.");
      if (ticket === null) return;
    }
    b.disabled = true;
    try {
      const job = await post("/api/jobs", { rc_id: b.dataset.raise, team: b.dataset.team, mode: b.dataset.mode, ticket });
      location.hash = `#/job/${job.pk}`;
    } catch (err) { alert(err.message); b.disabled = false; }
  }));
}
const jobsIfAllowed = async () => (can("M-PJ") ? (await api("/api/jobs")).jobs : []);

// ---------- screens: load() fetches what the screen needs, html() draws it, wire() adds behaviour ----------
const VIEWS = {};

VIEWS.board = {
  load: () => api("/api/board"),
  html(d) {
    const h = d.headline, cov = d.coverage, p = d.portfolio_labels;
    const total = d.root_causes.length || 1;
    const stack = SSVC_ORDER.map((k) => `<div class="${ssvcClass(k)}" style="width:${((h.ssvc[k] || 0) / total) * 100}%" title="${k}: ${h.ssvc[k] || 0}"></div>`).join("");
    const act = d.root_causes.filter((r) => r.ssvc === "Act");
    const scope = ME.modules.find((m) => m.key === "M-BRD").scope.join(", ");
    return `
      <h1>How exposed are we, in rupees?</h1>
      <p class="sub">${esc(num(d.raw_rows))} scanner detections, merged and grouped by the one fix that closes them. Scope: ${esc(scope)}.</p>
      <div class="grid kpis">
        <div class="card kpi"><div class="label">Expected annual loss</div><div class="value">${esc(p.ale_mean)}</div>
          <div class="note">80% range ${esc(p.ale_p10)} to ${esc(p.ale_p90)}</div></div>
        <div class="card kpi"><div class="label">Work to do</div><div class="value">${h.root_causes} fixes</div>
          <div class="note">${num(d.raw_rows)} detections → ${num(h.findings)} unique findings → ${h.root_causes} root causes</div></div>
        <div class="card kpi"><div class="label">Top ${h.top_n} fixes close</div><div class="value">${pct(h.top_risk_share)} of ₹ risk</div>
          <div class="note">and ${pct(h.top_findings_share)} of all findings</div></div>
        <div class="card kpi"><div class="label">CEA fix clock</div><div class="value">${num(h.cea_overdue)} past window</div>
          <div class="note">1-month (critical, high) or 3-month window, applies from 1 Apr 2027. Top ${h.top_n} clear ${num(h.cea_overdue_closed_by_top)}.</div></div>
      </div>
      <div class="grid two">
        <div class="card"><h2>Triage (CISA SSVC)</h2>
          <div class="stack">${stack}</div>
          <div class="legend">${SSVC_ORDER.map((k) => `<span>${ssvc(k)} ${h.ssvc[k] || 0}</span>`).join("")}</div>
          ${act.length ? `<p style="margin:12px 0 0">Act now: ${act.map((r) => `${esc(r.id)} ${esc(r.title)}`).join("; ")}.</p>` : ""}
        </div>
        <div class="card kpi"><h2>Coverage: what we cannot see</h2>
          <div class="grid three" style="gap:8px">
            <div><div class="value">${cov.scanned_assets}</div><div class="note">assets scanned</div></div>
            <div><div class="value" style="color:var(--act)">${cov.unscanned}</div><div class="note">registered, never scanned</div></div>
            <div><div class="value" style="color:var(--attend)">${cov.unknown}</div><div class="note">found, not in CMDB</div></div>
          </div>
          <div class="note" style="margin-top:8px"><b>${cov.unowned}</b> assets have no owning team in the ownership chart, so nobody is asked to fix them.</div>
          <div class="note" style="margin-top:8px">Unscanned assets carry risk this figure does not count.</div>
        </div>
      </div>
      <div class="grid two" style="margin-top:14px">
        <div class="card"><h2>Risk by business process</h2>${bars(d.risk_by_process.slice(0, 8))}</div>
        <div class="card"><h2>Risk by site</h2>${bars(d.risk_by_site)}</div>
      </div>
      <div class="card mt">
        <div class="toolbar" style="justify-content:space-between"><h2 style="margin:0">Top ${h.top_n} root causes, ranked by rupee risk</h2>
          <a class="btn" href="/api/board/pack" target="_blank" rel="noopener">Open board pack (prints to one page)</a></div>
        ${rcTable(d.root_causes.slice(0, h.top_n), { compact: true })}
      </div>`;
  },
  wire: wireRows,
};

VIEWS.queue = {
  load: () => api("/api/root-causes"),
  html(d) {
    const kinds = [...new Set(d.root_causes.map((r) => r.kind))];
    return `
      <h1>Root-cause queue</h1>
      <p class="sub">${d.root_causes.length} fixes instead of ${num(d.headline.findings)} findings. Click a row for the evidence.</p>
      <div class="toolbar">
        <input type="search" id="q" placeholder="Search title, CVE, owner…" style="min-width:240px">
        <select id="f-ssvc"><option value="">All SSVC</option>${SSVC_ORDER.map((k) => `<option>${k}</option>`).join("")}</select>
        <select id="f-kind"><option value="">All types</option>${kinds.map((k) => `<option value="${esc(k)}">${esc(KIND[k] || k)}</option>`).join("")}</select>
        <select id="f-ot"><option value="">IT and OT</option><option value="it">IT only</option><option value="ot">OT only</option></select>
        <a class="btn" href="/api/downloads/root_causes.csv">Export CSV</a>
        <a class="btn" href="/api/downloads/receipts.json">Receipts</a>
      </div>
      <div class="card" id="queue-table"></div>`;
  },
  wire(root, d) {
    const draw = () => {
      const q = root.querySelector("#q").value.trim().toLowerCase();
      const s = root.querySelector("#f-ssvc").value, k = root.querySelector("#f-kind").value, ot = root.querySelector("#f-ot").value;
      const rows = d.root_causes.filter((r) => (!s || r.ssvc === s) && (!k || r.kind === k) &&
        (!ot || (ot === "ot") === r.is_ot) &&
        (!q || [r.title, r.fix, r.id, ...r.owners, ...r.cves.map((c) => c.id)].join(" ").toLowerCase().includes(q)));
      const box = root.querySelector("#queue-table");
      box.innerHTML = rows.length ? rcTable(rows) : '<p class="muted">No root causes match.</p>';
      wireRows(box);
    };
    root.querySelectorAll("#q, #f-ssvc, #f-kind, #f-ot").forEach((el) => el.addEventListener("input", draw));
    draw();
  },
};

VIEWS.rc = {
  async load(id) { const [d, jobs] = await Promise.all([api("/api/root-causes"), jobsIfAllowed()]); d.jobs = jobs; d.rcId = id; return d; },
  html(d) {
    const r = d.root_causes.find((x) => x.id === d.rcId);
    if (!r) return `<div class="error">No root cause ${esc(d.rcId)} in your scope.</div>`;
    const ri = r.risk_inputs;
    const findings = r.finding_ids.map((f) => d.findings[f]);
    const kev = r.cves.filter((c) => c.exploitation === "active");
    const asset = (a) => d.assets[a];
    const myTeams = ME.raise_for_teams.filter((t) => r.owners.includes(t));
    const jobs = d.jobs.filter((j) => j.rc_current_id === r.id);
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
      ${can("M-PJ") || myTeams.length ? `<div class="card mt"><div class="toolbar" style="justify-content:space-between;margin:0"><h2 style="margin:0">Patch jobs</h2>
        <div>${raiseButtons(r, myTeams, d.jobs)}</div></div>
        ${jobs.length ? jobTable(jobs) : `<p class="muted" style="margin-bottom:0">No jobs yet. Owning teams: ${esc(r.owners.join(", ") || "none mapped")}.</p>`}</div>` : ""}
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
  wire(root) { wireRaise(root); wireRows(root); },
};

VIEWS.assets = {
  load: () => api("/api/assets"),
  html(d) {
    const cov = d.coverage;
    const asset = (a) => d.assets[a];
    const counts = {};
    Object.values(d.findings).forEach((f) => (counts[f.asset_id] = (counts[f.asset_id] || 0) + 1));
    d.counts = counts;
    const row = (x) => `<tr><td><b>${esc(x.hostname)}</b> ${x.is_ot ? otBadge(true) : ""}</td><td class="mono">${esc(x.ip)}</td>
      <td>${esc(x.site || "–")}</td><td>${esc(x.zone)}</td><td>${esc(x.owner || "–")}</td><td class="n">${x.criticality}</td></tr>`;
    return `
      <h1>Assets and coverage</h1>
      <p class="sub">Sutra shows what it cannot see. Blind spots are listed before the inventory.</p>
      <div class="grid kpis">
        <div class="card kpi"><div class="label">In the CMDB</div><div class="value">${cov.cmdb_assets}</div></div>
        <div class="card kpi"><div class="label">Scanned</div><div class="value">${cov.scanned_assets}</div><div class="note">${cov.multi_scanner_findings} findings confirmed by both scanners</div></div>
        <div class="card kpi"><div class="label">Never scanned</div><div class="value" style="color:var(--act)">${cov.unscanned.length}</div><div class="note">${cov.unscanned.filter((a) => asset(a).criticality >= 5).length} crown-jewel, ${cov.unscanned.filter((a) => asset(a).is_ot).length} OT</div></div>
        <div class="card kpi"><div class="label">Not in the CMDB</div><div class="value" style="color:var(--attend)">${cov.unknown.length}</div><div class="note">${cov.inferred_images.length} matched to a golden image</div></div>
      </div>
      <div class="card" style="margin-bottom:14px"><h2>No owning team (${cov.unowned.length})</h2>
        <p class="muted" style="margin-top:0">Assets whose owner is missing from the asset register or the ownership chart. Nobody is asked to fix their findings until a team owns them.</p>
        <div class="table-wrap"><table><thead><tr><th>Host</th><th>IP</th><th>Site</th><th>Owner in register</th><th class="n">Findings</th></tr></thead>
        <tbody>${cov.unowned.slice(0, 200).map((a) => { const x = asset(a); return `<tr><td><b>${esc(x.hostname)}</b>${x.in_cmdb ? "" : ' <span class="badge warn">not in CMDB</span>'}</td><td class="mono">${esc(x.ip)}</td>
          <td>${esc(x.site || "–")}</td><td>${esc(x.in_cmdb ? x.owner || "none" : "–")}</td><td class="n">${counts[a] || 0}</td></tr>`; }).join("") || '<tr><td colspan="5" class="muted">None</td></tr>'}</tbody></table></div></div>
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
  wire(root, d) {
    const all = Object.values(d.assets).sort((a, b) => b.criticality - a.criticality || a.hostname.localeCompare(b.hostname));
    const draw = () => {
      const q = root.querySelector("#aq").value.trim().toLowerCase();
      const rows = all.filter((x) => !q || [x.hostname, x.ip, x.owner, x.image, x.site, x.os, x.process].join(" ").toLowerCase().includes(q)).slice(0, 400);
      root.querySelector("#asset-rows").innerHTML = rows.map((x) => `<tr><td><b>${esc(x.hostname)}</b> ${x.is_ot ? otBadge(true) : ""}${x.in_cmdb ? "" : ' <span class="badge warn">not in CMDB</span>'}</td>
        <td class="mono">${esc(x.ip)}</td><td>${esc(x.site || "–")}</td><td>${esc(x.zone)}</td><td>${esc(x.owner || "–")}</td><td class="n">${x.criticality}</td>
        <td>${esc(x.image || "–")}</td><td>${x.scanned_by.length ? esc(x.scanned_by.join(", ")) : '<span class="badge warn">none</span>'}</td><td class="n">${d.counts[x.id] || 0}</td></tr>`).join("");
    };
    root.querySelector("#aq").addEventListener("input", draw);
    draw();
  },
};

VIEWS.portal = {
  async load() {
    const [d, jobs, changes] = await Promise.all([api("/api/portal"), jobsIfAllowed(), api("/api/history/changes").catch(() => null)]);
    d.jobs = jobs; d.changes = changes; return d;
  },
  html(d) {
    const scope = ME.modules.find((m) => m.key === "M-TP").scope.join(", ");
    if (!d.teams.length) return `<h1>Team portal</h1><p class="sub">No assets in your scope (${esc(scope)}).</p>`;
    return `
      <h1>${d.teams.length === 1 ? esc(d.teams[0].owner) : "Team portal"}</h1>
      <p class="sub">You see the assets in your scope: ${esc(scope)}. Build a patch job and Sutra drafts it and routes it for approval by criticality, or fix it yourself and attach the change ticket. Either way, a rescan closes it.</p>
      ${d.teams.map((t) => {
        const ids = new Set(Object.values(d.assets).filter((a) => (a.owner || "(no owner: not in CMDB)") === t.owner).map((a) => a.id));
        const findings = Object.values(d.findings).filter((f) => ids.has(f.asset_id)).length;
        const rcs = t.tasks.map((x) => d.root_causes.find((r) => r.id === x.id)).filter(Boolean);
        const mayRaise = ME.raise_for_teams.includes(t.owner);
        const ch = d.changes && d.changes.teams.find((x) => x.team === t.owner);
        return `<div class="card mt"><div class="owner-head"><h2>${esc(t.owner)}</h2><span class="muted">${esc(inr(t.ale))} / yr</span></div>
          <div class="muted" style="font-size:13px;margin:-4px 0 10px">${t.in_chart ? `Jira <span class="mono">${esc(t.jira || "–")}</span> · manager ${esc(t.manager || "–")} · ${esc(t.vertical || "no vertical")}${t.vertical_head ? `, headed by ${esc(t.vertical_head)}` : ""}` : "Not in the ownership chart, so jobs cannot be routed for approval."}
            · ${ids.size} assets · ${num(findings)} open findings</div>
          ${ch ? `<p style="margin:0 0 10px">Since the import of ${esc(fmtDate(d.changes.from.as_of))}: <b>${ch.fixed}</b> fixed, <b>${ch.new}</b> new, ${ch.still_open} still open${ch.not_rescanned ? `, ${ch.not_rescanned} not rescanned` : ""}. <a href="#/changes">Details</a></p>` : ""}
          <div class="table-wrap"><table><thead><tr><th>Root cause</th><th class="n">Hosts</th><th>SSVC</th><th class="n">₹ risk / yr</th><th>Due</th>${mayRaise ? "<th>Action</th>" : ""}</tr></thead>
          <tbody>${t.tasks.map((x) => { const r = rcs.find((y) => y.id === x.id); return `<tr ${can("M-RC") ? `class="click" data-rc="${esc(x.id)}"` : ""}><td><div class="t">${esc(x.title)} ${x.is_ot ? otBadge(true) : ""}</div><div class="fix">${esc(x.fix)}</div></td>
            <td class="n">${x.my_hosts}</td><td>${ssvc(x.ssvc)}</td><td class="n">${esc(x.ale_label)}</td><td>${dueLabel(x.earliest_due)}</td>
            ${mayRaise ? `<td style="white-space:nowrap">${r ? raiseButtons(r, [t.owner], d.jobs) : ""}</td>` : ""}</tr>`; }).join("")}</tbody></table></div>
          ${can("M-PJ") ? `<h2 style="margin-top:14px">Jobs</h2>${jobTable(d.jobs.filter((j) => j.team === t.owner))}` : ""}</div>`;
      }).join("")}`;
  },
  wire(root) { wireRaise(root); wireRows(root); },
};

VIEWS.jobs = {
  load: () => api("/api/jobs"),
  html(d) {
    return `
      <h1>Patch jobs and approvals</h1>
      <p class="sub">Who approves depends on fixed rules: SSVC category, asset criticality and whether the asset is OT. A drafted job cannot lower its own approval level.</p>
      ${can("M-PJ", "approve") ? `<div class="card"><h2>Waiting for you</h2>${jobTable(d.waiting_for_me)}</div>` : ""}
      <div class="card mt"><h2>Jobs in your scope</h2>${jobTable(d.jobs)}</div>
      <div class="card mt"><h2>Approval chain</h2><div class="table-wrap"><table>
        <thead><tr><th>Job type</th><th>Team</th><th>Manager</th><th>VM analyst</th><th>Vertical head</th></tr></thead><tbody>
        <tr><td>Track, non-critical IT asset</td><td>Raises job</td><td>Approves</td><td>Approves</td><td class="muted">Not needed</td></tr>
        <tr><td>Attend or Track*, or a crown-jewel IT asset</td><td>Raises job</td><td>Approves</td><td>Approves</td><td>Approves</td></tr>
        <tr><td>Act (actively exploited)</td><td>Raises job</td><td>Approves</td><td>Approves</td><td>Approves; can fast-track as an emergency change</td></tr>
        <tr><td>Any OT asset</td><td>Raises a staged plan</td><td>Approves</td><td>Approves</td><td>Approves, plus OEM approval and a shutdown slot</td></tr>
        </tbody></table></div>
        <p class="muted" style="margin-bottom:0">The person who raised a job cannot approve it, and nobody signs two steps of the same job. Thresholds are set under Administration.</p></div>`;
  },
  wire: wireRows,
};

VIEWS.job = {
  load: (id) => api(`/api/jobs/${encodeURIComponent(id)}`),
  html(j) {
    const d = j.draft;
    const cur = j.steps.find((s) => s.state === "current");
    const stepState = { waiting: "Waiting", current: "Needs decision", approved: "Approved", rejected: "Rejected", "sent-back": "Sent back" };
    return `
      <div class="crumb"><a href="#/jobs">← Patch jobs</a></div>
      <h1>${esc(j.id)}: ${esc(j.rc_title)}</h1>
      <div class="chips">${jobStatus(j)} ${ssvc(j.ssvc)} ${otBadge(j.is_ot)} <span class="badge">${esc(j.team)}</span>
        <span class="badge mono">Jira ${esc(j.jira)}</span> ${j.rc_current_id ? (can("M-RC") ? `<a class="badge" href="#/rc/${esc(j.rc_current_id)}">${esc(j.rc_current_id)}</a>` : `<span class="badge">${esc(j.rc_current_id)}</span>`) : '<span class="badge">Not in the latest import</span>'}
        ${j.route && j.route.emergency ? '<span class="badge warn">Emergency change allowed</span>' : ""}</div>
      ${j.route ? `<div class="card"><h2>Approval route</h2><p class="muted" style="margin-top:0">${esc(j.route.reason)}.</p>
        <div class="route"><div class="step approved"><div class="role">Team</div><div class="who">${esc(j.raised_by)}</div><div class="st">Raised</div></div>
        ${j.steps.map((s) => `<div class="step ${esc(s.state)}"><div class="role">${esc(s.label)}</div><div class="who">${esc(s.decided_by || s.who || "Any VM analyst")}</div>
          <div class="st">${esc(stepState[s.state])}${s.at ? ` · ${esc(fmtTime(s.at))}` : ""}</div>${s.comment ? `<div class="note-demo">“${esc(s.comment)}”</div>` : ""}</div>`).join("")}
        ${j.is_ot ? `<div class="step ${j.status === "approved" ? "current" : "waiting"}"><div class="role">Plant</div><div class="who">Plant engineer</div><div class="st">${j.status === "approved" ? "Executes at shutdown" : "After approval"}</div></div>` : ""}</div>
        ${j.can_decide ? `<div style="margin-top:12px"><textarea id="comment" maxlength="500" placeholder="Comment (optional)"></textarea>
          <div class="toolbar" style="margin-top:8px"><button class="btn primary" data-act="approve">Approve${j.route.emergency && cur.role === "vertical_head" ? " as emergency change" : ""}</button>
          <button class="btn" data-act="sendback">Send back</button><button class="btn" data-act="reject">Reject</button></div></div>` :
          cur ? `<p class="muted" style="margin-bottom:0">Waiting for ${esc(cur.who || "a VM analyst")}.${j.waiting_reason && can("M-PJ", "approve") ? ` ${esc(j.waiting_reason)}` : ""}</p>` : ""}
        </div>` : `<div class="card"><h2>Manual fix</h2><p style="margin:0">The team is fixing this by hand${j.ticket ? ` under change ticket <b class="mono">${esc(j.ticket)}</b>` : ""}. The findings close only when a rescan proves the fix.</p></div>`}
      ${j.status === "drafting" ? '<div class="card mt"><h2>Drafting</h2><p style="margin:0">Sutra is writing the draft. The first approval step opens when it is ready. <a href="">Refresh</a></p></div>' : ""}
      ${j.status === "draft-failed" ? '<div class="card mt"><h2>Draft failed</h2><p style="margin:0">Sutra could not write a draft for this job, so it was closed without approvals. Raise it again; if it fails again, tell your Sutra administrator.</p></div>' : ""}
      ${d && d.lane ? draftHtml(j, d) : ""}
      ${d && !d.lane ? `<div class="grid two" style="margin-top:14px">
        <div class="card"><h2>${j.is_ot ? "Staged plan" : "Patch job"} drafted by Sutra</h2>
          <p style="margin-top:0">${esc(d.summary)}</p>
          <dl class="kv"><dt>Tool</dt><dd>${esc(d.tool)}</dd><dt>Window</dt><dd>${esc(d.window)}</dd>
          <dt>Changes</dt><dd>${d.changes.map(esc).join("<br>")}</dd>
          ${d.oem_approval ? `<dt>OEM approval</dt><dd><span class="badge warn">${esc(d.oem_approval)}</span></dd><dt>Hold with</dt><dd>${esc(d.compensating_control)}</dd>` : ""}
          <dt>Rings</dt><dd>${d.rings.map((r) => `${esc(r.name)}: ${r.hosts.length} host${r.hosts.length === 1 ? "" : "s"}`).join("<br>")}</dd></dl>
          <p class="note-demo">Drafted from templates. Approval routing never depends on the draft.</p></div>
        <div class="card"><h2>Pre-checks and rollback</h2><ul style="margin-top:0">${d.prechecks.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>
          <p><b>Rollback:</b> ${esc(d.rollback)}</p>
          <p class="muted" style="margin-bottom:0">Targets: ${d.targets.map(esc).join(", ")}</p></div></div>
      <div class="card mt"><h2>${j.is_ot ? "Plan steps" : "Playbook"}</h2><pre class="playbook">${esc(d.playbook)}</pre></div>` : ""}
      <div class="card mt"><h2>Audit trail</h2><div class="table-wrap"><table>
        <thead><tr><th>When</th><th>Who</th><th>What</th><th>Comment</th></tr></thead>
        <tbody>${j.audit.map((a) => `<tr><td class="mono">${esc(fmtTime(a.at))}</td><td>${esc(a.actor || "Sutra")}</td><td>${esc(a.action)}</td><td>${esc(a.comment)}</td></tr>`).join("")}</tbody></table></div></div>`;
  },
  wire(root, j) {
    root.querySelectorAll("[data-act]").forEach((b) => b.addEventListener("click", async () => {
      b.disabled = true;
      try {
        await post(`/api/jobs/${j.pk}/decision`, { action: b.dataset.act, comment: root.querySelector("#comment").value });
        refreshInbox(); render();
      } catch (err) { alert(err.message); b.disabled = false; }
    }));
  },
};

function cites(list) {
  if (!list || !list.length) return "";
  // Name the root cause, hosts and changes; count findings, which can run to hundreds.
  const named = [...new Set(list.filter((c) => c.kind !== "finding").map((c) => c.label))];
  const findings = list.filter((c) => c.kind === "finding").length;
  const parts = named.slice(0, 6).map(esc);
  if (named.length > 6) parts.push(`${named.length - 6} more`);
  if (findings) parts.push(`${findings} finding${findings === 1 ? "" : "s"}`);
  const full = list.map((c) => `${c.kind} ${c.id}: ${c.label}`).join("\n");
  return `<div class="fix" title="${esc(full)}">Based on: ${parts.join("; ")}</div>`;
}
function draftHtml(j, d) {
  const by = d.source === "ai" ? `Drafted by Claude${d.model ? ` (${esc(d.model)})` : ""} and checked by Sutra against the scan data.` :
    `Drafted from Sutra's templates.${d.fallback_reason ? ` ${esc(d.fallback_reason)}.` : ""}`;
  return `<div class="grid two" style="margin-top:14px">
    <div class="card"><h2>${d.lane === "ot" ? "Staged plan" : "Patch job"}</h2>
      <p style="margin-top:0">${esc(d.summary)}</p>
      <dl class="kv"><dt>${d.lane === "ot" ? "Carried out by" : "Tool"}</dt><dd>${esc(d.tool)}</dd><dt>Window</dt><dd>${esc(d.window)}</dd>
      <dt>Changes</dt><dd>${d.changes.map((c) => `${esc(c.text)} <span class="muted">(${c.hosts.length} host${c.hosts.length === 1 ? "" : "s"})</span>`).join("<br>")}</dd>
      ${d.oem_approval ? `<dt>OEM approval</dt><dd><span class="badge warn">${esc(d.oem_approval)}</span></dd>` : ""}</dl>
      ${d.compensating_controls.length ? `<h2 style="margin-top:12px">Until the fix: compensating controls</h2><ul style="margin-top:0">${d.compensating_controls.map((c) => `<li>${esc(c.control)} <span class="muted">(${c.hosts.map(esc).join(", ")})</span>${cites(c.cites)}</li>`).join("")}</ul>` : ""}
      <p class="note-demo">${by} Who approves comes from fixed rules, never from the draft.</p>
      ${d.warnings.length ? `<p class="muted">${d.warnings.map(esc).join("<br>")}</p>` : ""}</div>
    <div class="card"><h2>Rings</h2><div class="table-wrap"><table><thead><tr><th>Ring</th><th>Hosts</th><th>Window</th></tr></thead><tbody>
      ${d.rings.map((r) => `<tr><td><b>${esc(r.name)}</b><div class="fix">${esc(r.purpose)}</div></td><td>${r.hosts.map(esc).join(", ")}</td><td>${esc(r.window)}</td></tr>`).join("")}</tbody></table></div>
      ${d.excluded.length ? `<p><b>Left out:</b> ${d.excluded.map((e) => `${esc(e.hostname || e.asset_id)}: ${esc(e.reason)}`).join("; ")}</p>` : ""}</div></div>
    ${d.oem_request ? `<div class="card mt"><h2>OEM approval request</h2><p style="margin-top:0">${esc(d.oem_request.detail)}</p><p class="muted">${d.oem_request.changes.map(esc).join("<br>")}</p>${cites(d.oem_request.cites)}</div>` : ""}
    <div class="card mt"><h2>${d.lane === "ot" ? "Plan steps" : "Steps"}</h2><ol class="steps">
      ${d.steps.map((s) => `<li><b>${esc(s.label)}</b>${s.ring ? ` <span class="badge">Ring ${s.ring}</span>` : ""}${s.changes.length ? ` <span class="muted">${s.changes.map(esc).join("; ")}</span>` : ""}<div>${esc(s.detail)}</div>${cites(s.cites)}</li>`).join("")}</ol></div>
    <div class="grid two" style="margin-top:14px">
      <div class="card"><h2>Pre-checks</h2><ul style="margin-top:0">${d.prechecks.map((x) => `<li>${esc(x.text)}${cites(x.cites)}</li>`).join("")}</ul></div>
      <div class="card"><h2>Rollback</h2><p style="margin-top:0"><b>When:</b> ${esc(d.rollback.trigger)}</p><ol>${d.rollback.steps.map((x) => `<li>${esc(x)}</li>`).join("")}</ol>${cites(d.rollback.cites)}</div></div>
    ${d.assumptions.length ? `<div class="card mt"><h2>Assumptions to check</h2><ul style="margin:0">${d.assumptions.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>` : ""}`;
}

VIEWS.changes = {
  async load(arg) {
    const imports = await api("/api/history/imports");
    const [from, to] = (arg || "").split("..");
    let changes = null, error = "";
    if (imports.length > 1) {
      try { changes = await api(`/api/history/changes?${from ? `from_id=${encodeURIComponent(from)}&` : ""}${to ? `to_id=${encodeURIComponent(to)}` : ""}`); }
      catch (e) { error = e.message; }
    }
    return { imports, changes, error };
  },
  html(d) {
    const label = (i) => `${fmtDate(i.as_of)} · ${i.org || "upload"}${i.kind === "demo" ? " (synthetic)" : ""} · imported ${fmtTime(i.imported_at)}`;
    if (d.imports.length < 2) return `<h1>What changed</h1><p class="sub">Sutra compares two imports. Only ${d.imports.length} import exists so far; the next one will show what was fixed, what is new and what is still open.</p>`;
    const c = d.changes;
    if (!c) return `<h1>What changed</h1><div class="error">${esc(d.error)}</div>`;
    const opts = (sel) => d.imports.map((i) => `<option value="${i.id}" ${i.id === sel ? "selected" : ""}>${esc(label(i))}</option>`).join("");
    const t = c.totals;
    return `<h1>What changed</h1>
      <p class="sub">A finding counts as fixed only when its host was scanned again and the finding was gone. If the host was not scanned, it is listed as not rescanned.</p>
      <div class="toolbar"><label>From <select id="ch-from">${opts(c.from.id)}</select></label><label>To <select id="ch-to">${opts(c.to.id)}</select></label></div>
      <div class="grid kpis">
        <div class="card kpi"><div class="label">Fixed</div><div class="value" style="color:var(--good)">${num(t.fixed)}</div></div>
        <div class="card kpi"><div class="label">New</div><div class="value" style="color:var(--act)">${num(t.new)}</div></div>
        <div class="card kpi"><div class="label">Still open</div><div class="value">${num(t.still_open)}</div></div>
        <div class="card kpi"><div class="label">Not rescanned</div><div class="value" style="color:var(--attend)">${num(t.not_rescanned)}</div><div class="note">missing from the newer import, host not scanned</div></div>
      </div>
      <div class="card"><h2>Per team</h2><div class="table-wrap"><table><thead><tr><th>Team</th><th class="n">Fixed</th><th class="n">New</th><th class="n">Still open</th><th class="n">Not rescanned</th></tr></thead>
        <tbody>${c.teams.map((x, n) => `<tr ${c.detail ? `class="click" data-team="${n}"` : ""}><td><b>${esc(x.team)}</b></td><td class="n">${x.fixed}</td><td class="n">${x.new}</td><td class="n">${x.still_open}</td><td class="n">${x.not_rescanned}</td></tr>`).join("") || '<tr><td colspan="5" class="muted">Nothing in your scope.</td></tr>'}</tbody></table></div>
        ${c.detail ? '<p class="muted" style="margin-bottom:0">Click a team for the findings.</p>' : ""}</div>
      <div id="ch-detail"></div>`;
  },
  wire(root, d) {
    if (!d.changes) return;
    const go = () => (location.hash = `#/changes/${root.querySelector("#ch-from").value}..${root.querySelector("#ch-to").value}`);
    root.querySelectorAll("#ch-from, #ch-to").forEach((s) => s.addEventListener("change", go));
    const c = d.changes;
    root.querySelectorAll("tr[data-team]").forEach((tr) => tr.addEventListener("click", () => {
      const x = c.teams[Number(tr.dataset.team)];
      const sec = (k, title) => `<h2 style="margin-top:14px">${title} (${x.items[k].length})</h2>${VIEWS.changes.list(x.items[k])}`;
      root.querySelector("#ch-detail").innerHTML = `<div class="card mt"><h2>${esc(x.team)}</h2>${sec("fixed", "Fixed")}${sec("new", "New")}${sec("not_rescanned", "Not rescanned")}${sec("still_open", "Still open")}</div>`;
      root.querySelector("#ch-detail").scrollIntoView({ behavior: "smooth" });
    }));
  },
  list(items) {
    return items.length ? `<div class="table-wrap"><table><thead><tr><th>Host</th><th>Finding</th><th>Severity</th><th>Root cause</th><th>First seen</th></tr></thead><tbody>
      ${items.slice(0, 300).map((i) => `<tr><td>${esc(i.host)}</td><td>${esc(i.title)}${i.cves.length ? `<div class="fix">${esc(i.cves.join(", "))}</div>` : ""}</td><td>${esc(i.severity)}</td><td class="muted">${esc(i.root_cause)}</td><td>${fmtDate(i.first_seen)}</td></tr>`).join("")}
      </tbody></table></div>${items.length > 300 ? `<p class="muted">Showing 300 of ${items.length}.</p>` : ""}` : '<p class="muted">None.</p>';
  },
};

VIEWS.headline = {
  load: async () => ({}),
  html() {
    return `
      <h1>Headline check: are we exposed?</h1>
      <p class="sub">Type a CVE or product from today's news. The answer comes from the latest scans of the assets in your scope.</p>
      <form id="hc" class="toolbar"><input type="search" id="hq" maxlength="120" placeholder="CVE-2023-4966, log4j, FortiOS…" style="min-width:320px" required>
        <button class="btn primary">Check</button></form>
      <div class="toolbar">${["CVE-2023-4966", "CVE-2018-13379", "CVE-2019-0708", "log4j", "CVE-2024-3400"].map((q) => `<button class="btn" data-q="${q}">${q}</button>`).join("")}</div>
      <div id="hc-out"></div>`;
  },
  wire(root) {
    const out = root.querySelector("#hc-out");
    const run = async (q) => {
      root.querySelector("#hq").value = q;
      out.innerHTML = '<p class="muted">Checking…</p>';
      try {
        const r = await post("/api/headline", { query: q });
        const intel = r.intel ? ` <span class="badge kev">${esc(r.intel.exploitation === "active" ? "Known exploited" : "Public exploit")}: ${esc(r.intel.name)}</span>` : "";
        out.innerHTML = `<div class="card">
          <div class="answer ${r.exposed ? "yes" : "no"}">${r.exposed ? `Yes: ${r.hosts} host${r.hosts === 1 ? "" : "s"} exposed` : "Not found on any scanned host in your scope"}${intel}</div>
          <p class="muted">${r.exposed ? `${r.findings} findings · ${r.internet_hosts} internet-facing · ${r.ot_hosts} OT.` : ""}
            ${r.unscanned_note ? `${r.unscanned_note} registered assets are never scanned, so they are not covered by this answer.` : ""}</p>
          ${r.exposed ? `<h2>Fixes that close it</h2>${rcTable(r.root_causes, { compact: true })}
          <h2 style="margin-top:14px">Hosts</h2><p>${r.hosts_list.map((a) => `${esc(a.hostname)} <span class="muted mono">${esc(a.ip)}</span>`).join(" · ")}</p>` : ""}</div>`;
        wireRows(out);
      } catch (e) { out.innerHTML = `<div class="error">${esc(e.message)}</div>`; }
    };
    root.querySelector("#hc").addEventListener("submit", (e) => { e.preventDefault(); run(root.querySelector("#hq").value); });
    root.querySelectorAll("[data-q]").forEach((b) => b.addEventListener("click", () => run(b.dataset.q)));
  },
};

VIEWS.import = {
  async load() { const [u, ds] = await Promise.all([api("/api/data/uploads"), api("/api/data/datasets")]); return { ...u, datasets: ds }; },
  html(d) {
    const act = can("M-DAT", "act");
    return `
      <h1>Import data</h1>
      <p class="sub">Import scanner exports, an asset register and an ownership chart. Analysing them replaces the current data for everyone.</p>
      ${act ? `<div class="card"><h2>Your exports</h2>
        <p class="muted" style="margin-top:0">Supported: Qualys VM detection CSV, Tenable.sc or Tenable.io CSV, Nessus <code>.nessus</code> XML, an asset register CSV
          (<code>asset_id, hostname, ip, site, zone, os, owner, business_process, inr_per_hour, criticality, image, config_template, is_ot, safety_critical, personal_data</code>)
          and an ownership chart CSV (<code>team, jira_project, manager, manager_email, vertical, vertical_head, vertical_head_email, vm_analyst, vm_analyst_email</code>).</p>
        <label class="drop" id="drop" for="file">Drop files here or click to choose<input type="file" id="file" multiple hidden></label>
        <div style="margin-top:12px">${d.files.length ? `<table><thead><tr><th>File</th><th>Detected as</th><th class="n">Size</th></tr></thead><tbody>
          ${d.files.map((u) => `<tr><td>${esc(u.name)}</td><td><span class="badge ${u.format === "unknown" ? "warn" : ""}">${esc(u.format)}</span></td><td class="n">${num(Math.round(u.bytes / 1024))} KB</td></tr>`).join("")}</tbody></table>` : '<p class="muted">No files uploaded.</p>'}</div>
        <div class="toolbar" style="margin-top:12px"><input type="text" id="org-in" maxlength="200" placeholder="Organisation name">
          <button class="btn primary" id="analyze" ${d.files.length ? "" : "disabled"}>Analyse uploaded files</button>
          <button class="btn" id="clear" ${d.files.length ? "" : "disabled"}>Clear uploads</button></div>
        <div id="imp-msg"></div></div>
      <div class="card mt"><h2>Synthetic demo companies</h2>
        <p class="muted" style="margin-top:0">Invented companies for demonstrations, generated as Qualys CSV, Tenable CSV, two .nessus plant scans, a CMDB and an ownership chart. Every screen marks them as synthetic.</p>
        <div class="toolbar"><select id="demo-month"><option value="0">Base scan</option>${[1, 2, 3].map((m) => `<option value="${m}">${m} month${m > 1 ? "s" : ""} later</option>`).join("")}</select>
          ${Object.entries(d.profiles).map(([k, v]) => `<button class="btn" data-demo="${esc(k)}">Load ${esc(v)}</button>`).join("")}</div>
        <p class="muted" style="margin-bottom:0">Load the base scan first, then a later month, to see what changed between imports.</p></div>` : ""}
      <div class="card mt"><h2>Import history</h2>${d.datasets.length ? `<div class="table-wrap"><table><thead><tr><th>Scans as of</th><th>Imported</th><th>Organisation</th><th>Kind</th><th class="n">Findings</th><th>Files</th><th>By</th></tr></thead><tbody>
        ${d.datasets.map((x) => `<tr><td>${esc(fmtDate(x.as_of))}</td><td class="mono">${esc(fmtTime(x.at))}</td><td>${esc(x.org || "–")} ${x.current ? '<span class="badge">current</span>' : ""}</td><td>${x.kind === "demo" ? '<span class="badge warn">synthetic</span>' : "upload"}</td><td class="n">${x.summary.findings ?? "–"}</td>
          <td>${x.files.map((f) => esc(f.name)).join("<br>")}</td><td>${esc(x.by)}</td></tr>`).join("")}</tbody></table></div>` : '<p class="muted">Nothing imported yet.</p>'}</div>`;
  },
  wire(root) {
    if (!can("M-DAT", "act")) return;
    const msg = root.querySelector("#imp-msg");
    const fail = (e) => (msg.innerHTML = `<div class="error" style="margin-top:10px">${esc(e.message)}</div>`);
    const done = async () => { await refreshStatus(); location.hash = `#/${homeView()}`; };
    root.querySelectorAll("[data-demo]").forEach((b) => b.addEventListener("click", async () => {
      b.disabled = true; b.textContent = "Loading…";
      try { await post("/api/data/demo", { profile: b.dataset.demo, month: Number(root.querySelector("#demo-month").value) }); await done(); } catch (e) { fail(e); render(); }
    }));
    const upload = async (files) => {
      msg.innerHTML = '<p class="muted">Uploading…</p>';
      for (const f of files) {
        const fd = new FormData(); fd.append("file", f, f.name);
        try { await api("/api/data/uploads", { method: "POST", body: fd }); } catch (e) { return fail(new Error(`${f.name}: ${e.message}`)); }
      }
      render();
    };
    const drop = root.querySelector("#drop");
    root.querySelector("#file").addEventListener("change", (e) => upload([...e.target.files]));
    ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
    ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
    drop.addEventListener("drop", (e) => upload([...e.dataTransfer.files]));
    root.querySelector("#analyze").addEventListener("click", async (e) => {
      e.target.disabled = true; e.target.textContent = "Analysing…";
      try { await post("/api/data/analyze", { org: root.querySelector("#org-in").value }); await done(); }
      catch (err) { fail(err); e.target.disabled = false; e.target.textContent = "Analyse uploaded files"; }
    });
    root.querySelector("#clear").addEventListener("click", async () => { await api("/api/data/uploads", { method: "DELETE" }); render(); });
  },
};

VIEWS.audit = {
  load: () => api("/api/audit?limit=200"),
  html(d) {
    return `<h1>Audit log</h1>
      <p class="sub">Every sign-in, access change, refused request and action, newest first. Times are UTC.</p>
      <form class="toolbar" id="af"><input type="search" id="a-action" placeholder="Action starts with (e.g. job., admin., auth.)">
        <input type="search" id="a-actor" placeholder="Actor email contains"><button class="btn">Filter</button>
        <a class="btn" href="/api/audit.csv">Export CSV</a></form>
      <div class="card"><div class="table-wrap"><table><thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th><th>IP</th></tr></thead>
        <tbody id="a-rows">${auditRows(d.events)}</tbody></table></div>
        <div class="toolbar" style="margin:10px 0 0"><button class="btn" id="a-more" ${d.next_before_id ? "" : "hidden"}>Load older</button></div></div>`;
  },
  wire(root, d) {
    let next = d.next_before_id;
    const q = () => `action=${encodeURIComponent(root.querySelector("#a-action").value)}&actor=${encodeURIComponent(root.querySelector("#a-actor").value)}`;
    root.querySelector("#af").addEventListener("submit", async (e) => {
      e.preventDefault();
      const r = await api(`/api/audit?limit=200&${q()}`);
      root.querySelector("#a-rows").innerHTML = auditRows(r.events); next = r.next_before_id; root.querySelector("#a-more").hidden = !next;
    });
    root.querySelector("#a-more").addEventListener("click", async () => {
      const r = await api(`/api/audit?limit=200&before_id=${next}&${q()}`);
      root.querySelector("#a-rows").insertAdjacentHTML("beforeend", auditRows(r.events)); next = r.next_before_id; root.querySelector("#a-more").hidden = !next;
    });
  },
};
function auditRows(events) {
  return events.map((e) => `<tr><td class="mono">${esc(fmtTime(e.at))}</td><td>${esc(e.actor)}</td><td class="mono">${esc(e.action)}</td>
    <td class="mono">${esc(e.target)}</td><td class="mono detail">${esc(Object.entries(e.detail || {}).filter(([, v]) => v !== null && v !== undefined).map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`).join(" "))}</td>
    <td class="mono">${esc(e.ip)}</td></tr>`).join("") || '<tr><td colspan="6" class="muted">No events.</td></tr>';
}

// ---------- administration ----------
VIEWS.admin = {
  async load(tab) {
    const full = can("M-ADM", "admin");
    tab = full ? tab || "people" : ["rules", "maintenance"].includes(tab) ? tab : "rules";
    const d = { tab, full };
    if (full) d.catalog = await api("/api/admin/catalog");
    if (tab === "people") d.users = await api("/api/admin/users");
    if (tab === "ownership") d.teams = await api("/api/admin/ownership");
    if (tab === "rules") d.rules = await api("/api/admin/approval-rules");
    if (tab === "maintenance") d.maint = await api("/api/admin/maintenance");
    return d;
  },
  html(d) {
    const tabs = d.full ? [["people", "People and access"], ["ownership", "Ownership chart"], ["rules", "Approval thresholds"], ["maintenance", "Maintenance windows"], ["licences", "Modules and licences"]] : [["rules", "Approval thresholds"], ["maintenance", "Maintenance windows"]];
    return `<h1>Administration</h1>
      <div class="tabs">${tabs.map(([k, l]) => `<a href="#/admin/${k}" class="${k === d.tab ? "active" : ""}">${esc(l)}</a>`).join("")}</div>
      <div id="admin-msg"></div>
      ${ADMIN_TABS[d.tab].html(d)}`;
  },
  wire(root, d) { ADMIN_TABS[d.tab].wire(root, d); },
};
function adminMsg(root, html, kind = "ok") {
  root.querySelector("#admin-msg").innerHTML = `<div class="${kind === "ok" ? "notice" : "error"}">${html}</div>`;
  window.scrollTo(0, 0);
}
function scopePicker(cat, role, prefix) {
  const r = cat.roles.find((x) => x.key === role);
  if (!r || r.scope_type === "org") return `<input type="hidden" id="${prefix}-scope" value=""><span class="muted">Whole organisation</span>`;
  if (r.scope_type === "team") return `<select id="${prefix}-scope" required>${cat.teams.map((t) => `<option>${esc(t)}</option>`).join("") || "<option value=''>Upload the ownership chart first</option>"}</select>`;
  if (r.scope_type === "vertical") return `<select id="${prefix}-scope" required>${cat.verticals.map((t) => `<option>${esc(t)}</option>`).join("") || "<option value=''>Upload the ownership chart first</option>"}</select>`;
  return `<input type="text" id="${prefix}-scope" placeholder="Site name, as in the asset register" required>`;
}
const roleLabel = (r) => `${esc(ROLE_NAME[r.role] || r.role)}${r.scope_type === "org" ? "" : ` <span class="muted">(${esc(r.scope_type)}: ${esc(r.scope_value)})</span>`}`;

const ADMIN_TABS = {
  people: {
    html(d) {
      const cat = d.catalog;
      return `<div class="card"><h2>Add a person</h2>
        <form id="nu" class="form-grid">
          <label>Email<input type="email" id="nu-email" required maxlength="254"></label>
          <label>Name<input type="text" id="nu-name" required maxlength="120"></label>
          <label>Role<select id="nu-role">${cat.roles.map((r) => `<option value="${esc(r.key)}">${esc(r.name)}</option>`).join("")}</select></label>
          <label>Scope<span id="nu-scope-box"></span></label>
          <label>Access ends (optional; required for auditors)<input type="date" id="nu-exp"></label>
          <label class="check"><input type="checkbox" id="nu-sso"> Single sign-on only (no password)</label>
          <div><button class="btn primary">Add person</button></div>
        </form></div>
      <div class="card mt"><h2>People (${d.users.length})</h2><div class="table-wrap"><table>
        <thead><tr><th>Person</th><th>Roles</th><th>Extra or removed modules</th><th>Status</th><th>Last sign-in</th><th></th></tr></thead>
        <tbody>${d.users.map((u) => `<tr><td><b>${esc(u.name)}</b><div class="fix">${esc(u.email)}</div></td>
          <td>${u.roles.map(roleLabel).join("<br>") || '<span class="muted">none</span>'}</td>
          <td>${u.grants.map((g) => `${g.effect === "deny" ? "Removed" : "Added"} ${esc(g.module)} ${esc(g.action)}${g.scope_type !== "org" ? ` (${esc(g.scope_type)}: ${esc(g.scope_value)})` : ""}`).join("<br>") || '<span class="muted">–</span>'}</td>
          <td>${u.active ? "Active" : '<span class="badge warn">Disabled</span>'}${u.locked ? ' <span class="badge warn">Locked</span>' : ""}${u.expires_at ? `<div class="fix">until ${esc(fmtDate(u.expires_at))}</div>` : ""}${u.sso_linked ? '<div class="fix">SSO linked</div>' : ""}</td>
          <td class="mono">${esc(u.last_login_at ? fmtTime(u.last_login_at) : "never")}</td>
          <td>${u.id === ME.user.id ? '<span class="muted">you</span>' : `<button class="btn small" data-edit="${u.id}">Manage</button>`}</td></tr>`).join("")}</tbody></table></div></div>
      <div id="editor"></div>`;
    },
    wire(root, d) {
      const cat = d.catalog;
      const box = root.querySelector("#nu-scope-box");
      const role = root.querySelector("#nu-role");
      const drawScope = () => (box.innerHTML = scopePicker(cat, role.value, "nu"));
      role.addEventListener("change", drawScope); drawScope();
      root.querySelector("#nu").addEventListener("submit", async (e) => {
        e.preventDefault();
        const exp = root.querySelector("#nu-exp").value;
        const r = cat.roles.find((x) => x.key === role.value);
        try {
          const u = await post("/api/admin/users", { email: root.querySelector("#nu-email").value, name: root.querySelector("#nu-name").value,
            roles: [{ role: role.value, scope_type: r.scope_type, scope_value: root.querySelector("#nu-scope").value }],
            expires_at: exp ? `${exp}T23:59:59` : null, sso_only: root.querySelector("#nu-sso").checked });
          await render();
          adminMsg(view, u.temporary_password ? `Added ${esc(u.email)}. One-time password: <b class="mono">${esc(u.temporary_password)}</b>. Share it securely; they must change it at first sign-in. It is not shown again.` : `Added ${esc(u.email)} for single sign-on.`);
        } catch (err) { adminMsg(root, esc(err.message), "error"); }
      });
      root.querySelectorAll("[data-edit]").forEach((b) => b.addEventListener("click", () => editUser(root, cat, d.users.find((u) => u.id === Number(b.dataset.edit)))));
    },
  },
  ownership: {
    html(d) {
      return `<div class="card"><h2>Upload the ownership chart</h2>
        <p class="muted" style="margin-top:0">Columns: <code>team, jira_project, manager, manager_email, vertical, vertical_head, vertical_head_email, vm_analyst, vm_analyst_email</code>.
          The chart decides who may sign each approval step: the manager and vertical head emails must match the people's Sutra accounts. Uploading replaces the whole chart.</p>
        <div class="toolbar"><input type="file" id="own-file" accept=".csv,text/csv"><button class="btn primary" id="own-up">Upload and replace</button></div></div>
      <div class="card mt"><h2>Current chart (${d.teams.length} teams)</h2><div class="table-wrap"><table>
        <thead><tr><th>Team</th><th>Jira</th><th>Manager</th><th>Vertical</th><th>Vertical head</th><th>VM analyst</th></tr></thead>
        <tbody>${d.teams.map((t) => `<tr><td><b>${esc(t.team)}</b></td><td class="mono">${esc(t.jira_project)}</td>
          <td>${esc(t.manager_name)}<div class="fix">${esc(t.manager_email)}</div></td><td>${esc(t.vertical)}</td>
          <td>${esc(t.vertical_head_name)}<div class="fix">${esc(t.vertical_head_email)}</div></td>
          <td>${esc(t.vm_analyst_name)}<div class="fix">${esc(t.vm_analyst_email)}</div></td></tr>`).join("") || '<tr><td colspan="6" class="muted">No chart uploaded.</td></tr>'}</tbody></table></div></div>`;
    },
    wire(root) {
      root.querySelector("#own-up").addEventListener("click", async () => {
        const f = root.querySelector("#own-file").files[0];
        if (!f) return;
        const fd = new FormData(); fd.append("file", f, f.name);
        try { const r = await api("/api/admin/ownership", { method: "POST", body: fd }); await render(); adminMsg(view, `Loaded ${r.teams} teams.`); }
        catch (e) { adminMsg(root, esc(e.message), "error"); }
      });
    },
  },
  rules: {
    html(d) {
      const r = d.rules.rules;
      return `<div class="card"><h2>When the vertical head must approve</h2>
        <p class="muted" style="margin-top:0">The team manager and a VM analyst always approve, and every OT plan goes to the vertical head. Those rules cannot be changed here.</p>
        <form id="rules" class="stack-form">
          <fieldset><legend>SSVC decisions that need the vertical head</legend>
            ${d.rules.ssvc.map((s) => `<label class="check"><input type="checkbox" name="ssvc" value="${esc(s)}" ${r.vertical_head_for_ssvc.includes(s) ? "checked" : ""}> ${ssvc(s)}</label>`).join("")}</fieldset>
          <label>Also any job touching an asset with criticality at or above
            <select id="crit">${[1, 2, 3, 4, 5].map((n) => `<option ${n === r.crown_jewel_min_criticality ? "selected" : ""}>${n}</option>`).join("")}</select></label>
          <label class="check"><input type="checkbox" id="emerg" ${r.emergency_fast_track_for_act ? "checked" : ""}> The vertical head may approve an Act job as an emergency change</label>
          <div><button class="btn primary">Save thresholds</button></div>
        </form>
        <p class="muted" style="margin-bottom:0">New thresholds apply to jobs raised after saving. Every change is recorded in the audit log.</p></div>`;
    },
    wire(root) {
      root.querySelector("#rules").addEventListener("submit", async (e) => {
        e.preventDefault();
        try {
          await api("/api/admin/approval-rules", { method: "PUT", json: {
            vertical_head_for_ssvc: [...root.querySelectorAll("input[name=ssvc]:checked")].map((x) => x.value),
            crown_jewel_min_criticality: Number(root.querySelector("#crit").value),
            emergency_fast_track_for_act: root.querySelector("#emerg").checked } });
          adminMsg(root, "Saved.");
        } catch (err) { adminMsg(root, esc(err.message), "error"); }
      });
    },
  },
  maintenance: {
    html(d) {
      const m = d.maint.maintenance;
      const days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
      const sites = [...new Set([...d.maint.ot_sites, ...Object.keys(m.ot_shutdowns)])].sort();
      return `<div class="card"><h2>IT change window</h2>
        <p class="muted" style="margin-top:0">Patch-job drafts put each ring in the next weekly window after the day the job is raised, one week apart.</p>
        <form id="maint" class="stack-form">
          <label>Day <select id="m-day">${days.map((x, i) => `<option value="${i}" ${i === m.weekday ? "selected" : ""}>${x}</option>`).join("")}</select></label>
          <label>Starts at <input id="m-start" type="time" value="${esc(m.start)}" required></label>
          <label>Lasts (hours) <input id="m-dur" type="number" min="1" max="24" value="${m.duration_hours}" required></label>
          <label>Time zone label <input id="m-tz" maxlength="16" value="${esc(m.timezone_label)}" required></label>
          <h2 style="margin-top:10px">Next planned plant shutdown</h2>
          <p class="muted" style="margin-top:0">OT plans are scheduled only for a shutdown operations has named. Without a date the plan says the slot is not set. A plan that spans two sites gets no date.</p>
          ${sites.length ? `<div class="table-wrap"><table><thead><tr><th>Site</th><th>Shutdown date</th></tr></thead><tbody>
            ${sites.map((x) => `<tr><td>${esc(x)}</td><td><input type="date" data-site="${esc(x)}" value="${esc(m.ot_shutdowns[x] || "")}"></td></tr>`).join("")}</tbody></table></div>`
            : '<p class="muted">No OT sites in the current import.</p>'}
          <div><button class="btn primary">Save</button></div>
        </form>
        <p class="muted" style="margin-bottom:0">Drafts are written by ${d.maint.ai_drafting ? "Claude, checked against the scan data, with the templates as fallback" : "rule-based templates (no Anthropic API key is set)"}. New settings apply to jobs raised after saving.</p></div>`;
    },
    wire(root) {
      root.querySelector("#maint").addEventListener("submit", async (e) => {
        e.preventDefault();
        const ot = {};
        root.querySelectorAll("input[data-site]").forEach((i) => { if (i.value) ot[i.dataset.site] = i.value; });
        try {
          await api("/api/admin/maintenance", { method: "PUT", json: {
            weekday: Number(root.querySelector("#m-day").value), start: root.querySelector("#m-start").value,
            duration_hours: Number(root.querySelector("#m-dur").value), timezone_label: root.querySelector("#m-tz").value,
            ot_shutdowns: ot } });
          adminMsg(root, "Saved.");
        } catch (err) { adminMsg(root, esc(err.message), "error"); }
      });
    },
  },
  licences: {
    html(d) {
      return `<div class="card"><h2>Modules</h2>
        <p class="muted" style="margin-top:0">A module gives access only when it is built and licensed. Switching a licence off removes it from everyone at once.</p>
        <div class="table-wrap"><table><thead><tr><th>Module</th><th>Built</th><th>Licensed</th></tr></thead>
        <tbody>${d.catalog.modules.map((m) => `<tr><td><b>${esc(m.name)}</b> <span class="muted mono">${esc(m.key)}</span></td>
          <td>${m.built ? "Yes" : '<span class="muted">Not yet</span>'}</td>
          <td><label class="check"><input type="checkbox" data-lic="${esc(m.key)}" ${m.licensed ? "checked" : ""} ${m.key === "M-ADM" ? "disabled" : ""}> ${m.licensed ? "On" : "Off"}</label></td></tr>`).join("")}</tbody></table></div></div>
      <div class="card mt"><h2>Roles</h2><div class="table-wrap"><table><thead><tr><th>Role</th><th>Assigned per</th><th>Modules and actions</th></tr></thead>
        <tbody>${d.catalog.roles.map((r) => `<tr><td><b>${esc(r.name)}</b><div class="fix">${esc(r.description)}</div></td><td>${esc(r.scope_type)}${r.time_limited ? " (time-limited)" : ""}</td>
          <td class="mono">${r.permissions.map(esc).join("<br>")}</td></tr>`).join("")}</tbody></table></div></div>`;
    },
    wire(root) {
      root.querySelectorAll("[data-lic]").forEach((c) => c.addEventListener("change", async () => {
        try { await api(`/api/admin/modules/${encodeURIComponent(c.dataset.lic)}`, { method: "PATCH", json: { licensed: c.checked } }); await render(); }
        catch (e) { adminMsg(root, esc(e.message), "error"); c.checked = !c.checked; }
      }));
    },
  },
};

function editUser(root, cat, u) {
  const ed = root.querySelector("#editor");
  const modules = cat.modules.filter((m) => m.built);
  ed.innerHTML = `<div class="card mt"><div class="owner-head"><h2>${esc(u.name)} <span class="muted">${esc(u.email)}</span></h2><button class="btn small" id="ed-close">Close</button></div>
    <h3>Roles</h3>
    <div>${u.roles.map((r, i) => `<div class="toolbar" style="margin:0 0 6px">${roleLabel(r)} <button class="btn small" data-rm-role="${i}">Remove</button></div>`).join("") || '<p class="muted">No roles.</p>'}</div>
    <form id="ed-role" class="toolbar"><select id="er-role">${cat.roles.map((r) => `<option value="${esc(r.key)}">${esc(r.name)}</option>`).join("")}</select>
      <span id="er-scope-box"></span><button class="btn">Add role</button></form>
    <h3>Module exceptions for this person</h3>
    <div>${u.grants.map((g) => `<div class="toolbar" style="margin:0 0 6px">${g.effect === "deny" ? "Removed" : "Added"} <b>${esc(g.module)}</b> ${esc(g.action)}${g.scope_type !== "org" ? ` (${esc(g.scope_type)}: ${esc(g.scope_value)})` : ""} <span class="muted">${esc(g.reason)}</span>
      <button class="btn small" data-rm-grant="${g.id}">Undo</button></div>`).join("") || '<p class="muted">None.</p>'}</div>
    <form id="ed-grant" class="form-grid">
      <label>Change<select id="eg-effect"><option value="allow">Add a module action</option><option value="deny">Remove a module action</option></select></label>
      <label>Module<select id="eg-mod">${modules.map((m) => `<option value="${esc(m.key)}">${esc(m.name)}</option>`).join("")}</select></label>
      <label>Action<select id="eg-act">${cat.actions.map((a) => `<option>${esc(a)}</option>`).join("")}<option value="*">whole module (remove only)</option></select></label>
      <label>Scope<select id="eg-st"><option value="org">Whole organisation</option><option value="vertical">Vertical</option><option value="site">Site</option><option value="team">Team</option></select></label>
      <label>Scope value<input type="text" id="eg-sv" placeholder="Team, vertical or site name"></label>
      <label>Reason (kept in the audit log)<input type="text" id="eg-reason" required minlength="3" maxlength="500"></label>
      <div><button class="btn">Save exception</button></div></form>
    <h3>Account</h3>
    <div class="toolbar">
      <button class="btn" id="ed-active">${u.active ? "Disable account" : "Enable account"}</button>
      ${u.locked ? '<button class="btn" id="ed-unlock">Unlock</button>' : ""}
      <button class="btn" id="ed-reset">Reset password</button>
      <label>Access ends <input type="date" id="ed-exp" value="${u.expires_at ? esc(u.expires_at.slice(0, 10)) : ""}"></label><button class="btn" id="ed-exp-save">Save date</button>
    </div></div>`;
  ed.scrollIntoView({ behavior: "smooth" });
  const after = async (msg) => { await render(); if (msg) adminMsg(view, msg); const nu = (await api("/api/admin/users")).find((x) => x.id === u.id); if (nu) editUser(view, cat, nu); };
  const failed = (e) => adminMsg(root, esc(e.message), "error");
  const roleSel = ed.querySelector("#er-role");
  const drawScope = () => (ed.querySelector("#er-scope-box").innerHTML = scopePicker(cat, roleSel.value, "er"));
  roleSel.addEventListener("change", drawScope); drawScope();
  const putRoles = (roles) => api(`/api/admin/users/${u.id}/roles`, { method: "PUT", json: roles });
  const current = () => u.roles.map((r) => ({ role: r.role, scope_type: r.scope_type, scope_value: r.scope_value }));
  ed.querySelector("#ed-close").addEventListener("click", () => (ed.innerHTML = ""));
  ed.querySelector("#ed-role").addEventListener("submit", async (e) => {
    e.preventDefault();
    const r = cat.roles.find((x) => x.key === roleSel.value);
    try { await putRoles([...current(), { role: r.key, scope_type: r.scope_type, scope_value: ed.querySelector("#er-scope").value }]); await after("Role added. It applies from their next request."); } catch (err) { failed(err); }
  });
  ed.querySelectorAll("[data-rm-role]").forEach((b) => b.addEventListener("click", async () => {
    try { await putRoles(current().filter((_, i) => i !== Number(b.dataset.rmRole))); await after("Role removed."); } catch (err) { failed(err); }
  }));
  ed.querySelector("#ed-grant").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await post(`/api/admin/users/${u.id}/grants`, { effect: ed.querySelector("#eg-effect").value, module: ed.querySelector("#eg-mod").value,
        action: ed.querySelector("#eg-act").value, scope_type: ed.querySelector("#eg-st").value, scope_value: ed.querySelector("#eg-sv").value,
        reason: ed.querySelector("#eg-reason").value });
      await after("Exception saved.");
    } catch (err) { failed(err); }
  });
  ed.querySelectorAll("[data-rm-grant]").forEach((b) => b.addEventListener("click", async () => {
    try { await api(`/api/admin/grants/${b.dataset.rmGrant}`, { method: "DELETE" }); await after("Exception removed."); } catch (err) { failed(err); }
  }));
  const patch = (json, msg) => api(`/api/admin/users/${u.id}`, { method: "PATCH", json }).then(() => after(msg)).catch(failed);
  ed.querySelector("#ed-active").addEventListener("click", () => patch({ is_active: !u.active }, u.active ? "Account disabled and signed out." : "Account enabled."));
  const unlock = ed.querySelector("#ed-unlock");
  if (unlock) unlock.addEventListener("click", () => patch({ unlock: true }, "Account unlocked."));
  ed.querySelector("#ed-exp-save").addEventListener("click", () => {
    const v = ed.querySelector("#ed-exp").value;
    patch(v ? { expires_at: `${v}T23:59:59` } : { clear_expiry: true }, "Access end date saved.");
  });
  ed.querySelector("#ed-reset").addEventListener("click", async () => {
    if (!confirm(`Reset the password for ${u.email}? Their sessions end now.`)) return;
    try { const r = await post(`/api/admin/users/${u.id}/reset-password`, {}); await after(`New one-time password for ${esc(u.email)}: <b class="mono">${esc(r.temporary_password)}</b>. It is not shown again.`); } catch (err) { failed(err); }
  });
}

// ---------- account ----------
VIEWS.account = {
  load: async () => ({}),
  html() {
    const u = ME.user;
    return `<h1>Your account</h1>
      ${u.must_change_password ? '<div class="error">Choose a new password to continue.</div>' : ""}
      <div class="grid two" style="margin-top:14px">
        <div class="card"><h2>${esc(u.name)}</h2><dl class="kv"><dt>Email</dt><dd>${esc(u.email)}</dd>
          <dt>Roles</dt><dd>${ME.roles.map((r) => `${esc(ROLE_NAME[r.role] || r.role)} <span class="muted">(${esc(r.scope)})</span>`).join("<br>") || "None"}</dd>
          <dt>Modules</dt><dd>${ME.modules.map((m) => `${esc(m.name)} <span class="muted">${esc(m.actions.join(", "))}</span>`).join("<br>") || "None"}</dd>
          ${u.expires_at ? `<dt>Access ends</dt><dd>${esc(fmtDate(u.expires_at))}</dd>` : ""}
          <dt>Signed in with</dt><dd>${ME.session_method === "oidc" ? "Single sign-on" : "Password"}</dd></dl></div>
        ${u.has_password ? `<div class="card"><h2>Change password</h2>
          <form id="pw" class="stack-form">
            <label>Current password<input type="password" id="pw-cur" autocomplete="current-password" required></label>
            <label>New password (at least ${ME.min_password_length || 12} characters)<input type="password" id="pw-new" autocomplete="new-password" required minlength="12"></label>
            <label>New password again<input type="password" id="pw-new2" autocomplete="new-password" required></label>
            <button class="btn primary">Change password</button><div id="pw-msg"></div></form></div>` : ""}
      </div>`;
  },
  wire(root) {
    const f = root.querySelector("#pw");
    if (!f) return;
    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      const msg = root.querySelector("#pw-msg");
      if (f.querySelector("#pw-new").value !== f.querySelector("#pw-new2").value) { msg.innerHTML = '<div class="error">The new passwords do not match.</div>'; return; }
      try {
        await post("/api/auth/password", { current: f.querySelector("#pw-cur").value, new: f.querySelector("#pw-new").value });
        ME = await api("/api/auth/me");
        msg.innerHTML = '<div class="notice">Password changed. Other sessions were signed out.</div>';
        if (location.hash === "#/account") setTimeout(() => (location.hash = `#/${homeView()}`), 900);
        await start();
      } catch (err) { msg.innerHTML = `<div class="error">${esc(err.message)}</div>`; }
    });
  },
};

// ---------- router ----------
const NEEDS_DATA = new Set(["board", "queue", "rc", "assets", "portal", "headline"]);
let renderSeq = 0;
async function render() {
  if (!ME) return;
  const [name, arg] = (location.hash.replace(/^#\//, "").split("?")[0] || homeView()).split("/");
  let key = VIEWS[name] ? name : homeView();
  if (ME.user.must_change_password) key = "account";
  const owner = NAV.find((n) => n.view === (OWNER_VIEW[key] || key));
  if (owner && !allowed(owner)) key = homeView();
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.view === (OWNER_VIEW[key] || key)));
  const seq = ++renderSeq;
  if (NEEDS_DATA.has(key) && STATUS && !STATUS.loaded) { view.innerHTML = emptyState(); return; }
  view.innerHTML = '<div class="loading">Loading…</div>';
  try {
    D = await VIEWS[key].load(decodeURIComponent(arg || ""));
    if (seq !== renderSeq) return;
    view.innerHTML = VIEWS[key].html(D);
    (VIEWS[key].wire || (() => {}))(view, D);
    view.focus({ preventScroll: true });
  } catch (e) {
    if (e.status === 401) return;
    if (seq === renderSeq) view.innerHTML = `<div class="error">${esc(e.message)}</div>`;
  }
}

async function start() {
  try { ME = await api("/api/auth/me"); } catch (e) { if (e.status !== 401) showSignIn("Could not reach the Sutra server."); return; }
  try { const cfg = await (await fetch("/api/auth/config")).json(); ME.min_password_length = cfg.min_password_length; } catch (e) { /* default */ }
  document.getElementById("signin").hidden = true;
  document.getElementById("shell").hidden = false;
  buildNav();
  await refreshStatus();
  refreshInbox();
  await render();
}
window.addEventListener("hashchange", render);
start();
