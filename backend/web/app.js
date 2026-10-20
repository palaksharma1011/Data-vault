// ---- API helper ----
const API = {
  token: sessionStorage.getItem("vault_token") || null,
  headers(json) {
    const h = {};
    if (this.token) h["Authorization"] = "Bearer " + this.token;
    if (json) h["Content-Type"] = "application/json";
    return h;
  },
  async call(method, path, body, isForm) {
    const headers = this.headers(body && !isForm);
    const opts = { method, headers };
    if (body) opts.body = isForm ? body : JSON.stringify(body);
    const res = await fetch(path, opts);
    let data = null;
    try { data = await res.json(); } catch (e) { /* no body (e.g. 204) */ }
    if (!res.ok) {
      let msg = (data && data.error) || res.statusText;
      if (data && data.retryAfterSeconds) msg += ` (retry in ~${Math.ceil(data.retryAfterSeconds / 60)} min)`;
      const err = new Error(msg);
      err.status = res.status; err.data = data;
      throw err;
    }
    return data;
  },
};

let state = { user: null, view: "dashboard", mfaToken: null };

function setToken(t) {
  API.token = t;
  if (t) sessionStorage.setItem("vault_token", t); else sessionStorage.removeItem("vault_token");
}

// ---- Login (password step, then optional MFA step) ----
document.getElementById("login-btn").addEventListener("click", doLogin);
document.getElementById("login-password").addEventListener("keydown", (e) => { if (e.key === "Enter") doLogin(); });
document.getElementById("login-mfa-btn").addEventListener("click", doMfaLogin);
document.getElementById("login-mfa-code").addEventListener("keydown", (e) => { if (e.key === "Enter") doMfaLogin(); });
document.getElementById("login-mfa-back").addEventListener("click", showPasswordStep);

function showPasswordStep() {
  state.mfaToken = null;
  document.getElementById("login-step-mfa").classList.add("hidden");
  document.getElementById("login-step-password").classList.remove("hidden");
  document.getElementById("login-password").value = "";
  document.getElementById("login-mfa-code").value = "";
}

async function doLogin() {
  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;
  const errEl = document.getElementById("login-error");
  errEl.textContent = "";
  try {
    const data = await API.call("POST", "/api/login", { Username: username, Password: password });
    if (data.mfaRequired) {
      state.mfaToken = data.mfaToken;
      document.getElementById("login-step-password").classList.add("hidden");
      document.getElementById("login-step-mfa").classList.remove("hidden");
      document.getElementById("login-mfa-error").textContent = "";
      document.getElementById("login-mfa-code").focus();
      return;
    }
    await finishLogin(data.token);
  } catch (e) {
    errEl.textContent = e.message || "Login failed";
  }
}

async function doMfaLogin() {
  const errEl = document.getElementById("login-mfa-error");
  errEl.textContent = "";
  const code = document.getElementById("login-mfa-code").value.trim();
  try {
    const data = await API.call("POST", "/api/login/mfa", { mfaToken: state.mfaToken, code });
    await finishLogin(data.token);
  } catch (e) {
    errEl.textContent = e.message || "Verification failed";
    if (e.status === 401 && /expired|invalid/i.test(e.message) && !/code/i.test(e.message)) showPasswordStep();
  }
}

async function finishLogin(token) {
  setToken(token);
  state.user = await API.call("GET", "/api/me");
  showPasswordStep();
  enterApp();
}

document.getElementById("logout-btn").addEventListener("click", async () => {
  try { await API.call("POST", "/api/logout"); } catch (e) { /* already expired */ }
  setToken(null);
  state.user = null;
  document.getElementById("app-screen").classList.add("hidden");
  document.getElementById("login-screen").classList.remove("hidden");
});

async function tryResume() {
  if (!API.token) return;
  try {
    state.user = await API.call("GET", "/api/me");
    enterApp();
  } catch (e) { setToken(null); }
}

function isAdmin() { return state.user && state.user.role === "ADMIN"; }

function enterApp() {
  document.getElementById("login-screen").classList.add("hidden");
  document.getElementById("app-screen").classList.remove("hidden");
  document.getElementById("who-name").textContent = state.user.username;
  document.getElementById("who-role").textContent = state.user.role;
  state.view = state.user.mfaSetupRequired ? "security" : (isAdmin() ? "dashboard" : "files");
  render();
}

function buildNav() {
  let items;
  if (state.user.mfaSetupRequired) items = [["security", "🔐 Security (MFA required)"]];
  else if (isAdmin()) items = [["dashboard", "📊 Dashboard"], ["files", "🗂 Files & Policies"], ["users", "👤 Users"], ["audit", "📜 Audit Log"], ["security", "🔐 Security"]];
  else items = [["files", "🗂 My Access"], ["security", "🔐 Security"]];
  const nav = document.getElementById("nav");
  nav.innerHTML = "";
  items.forEach(([key, label]) => {
    const div = document.createElement("div");
    div.className = "nav-item" + (state.view === key ? " active" : "");
    div.textContent = label;
    div.onclick = () => { state.view = key; render(); };
    nav.appendChild(div);
  });
}

function esc(s) { const d = document.createElement("div"); d.textContent = s ?? ""; return d.innerHTML; }
function fmtDate(s) { return new Date(s).toLocaleString(); }

async function render() {
  buildNav();
  const main = document.getElementById("main-content");
  main.innerHTML = `<p class="muted">Loading…</p>`;
  try {
    if (state.view === "dashboard") await renderDashboard(main);
    else if (state.view === "files") await renderFiles(main);
    else if (state.view === "users") await renderUsers(main);
    else if (state.view === "audit") await renderAudit(main);
    else if (state.view === "security") await renderSecurity(main);
  } catch (e) {
    if (e.status === 401) { setToken(null); location.reload(); return; }
    main.innerHTML = `<p class="error-msg">${esc(e.message)}</p>`;
  }
}

// ---- Dashboard ----
async function renderDashboard(main) {
  const s = await API.call("GET", "/api/dashboard/summary");
  main.innerHTML = `
    <h2 class="page-title">Dashboard</h2>
    <div class="grid">
      <div class="stat-card"><div class="num">${s.totalUsers}</div><div class="label">Users</div></div>
      <div class="stat-card"><div class="num">${s.totalFiles}</div><div class="label">Files</div></div>
      <div class="stat-card"><div class="num">${s.totalPolicies}</div><div class="label">Policies</div></div>
      <div class="stat-card"><div class="num" style="color:var(--allow)">${s.allowCount}</div><div class="label">Allow Decisions</div></div>
      <div class="stat-card"><div class="num" style="color:var(--deny)">${s.denyCount}</div><div class="label">Deny Decisions</div></div>
    </div>
    <div class="card">
      <h3>Recent Security Events</h3>
      ${auditTable(s.recentAudit)}
    </div>`;
}

function auditTable(entries) {
  if (!entries || entries.length === 0) return `<p class="muted">No events recorded yet.</p>`;
  return `
    <table>
      <thead><tr><th>Time</th><th>User</th><th>Role</th><th>Event</th><th>Resource</th><th>Decision</th><th>Reason</th></tr></thead>
      <tbody>
        ${entries.map(e => `
          <tr>
            <td>${fmtDate(e.timestamp)}</td>
            <td>${esc(e.username) || "—"}</td>
            <td>${e.role ? `<span class="tag role">${esc(e.role)}</span>` : "—"}</td>
            <td>${esc(e.action)}</td>
            <td>${esc(e.resource) || "—"}</td>
            <td><span class="tag ${esc(e.decision)}">${esc(e.decision)}</span></td>
            <td class="muted">${esc(e.reason)}</td>
          </tr>`).join("")}
      </tbody>
    </table>`;
}

// ---- Files & Policies ----
async function renderFiles(main) {
  const files = await API.call("GET", "/api/files");
  let policies = [];
  if (isAdmin()) policies = await API.call("GET", "/api/policies");

  main.innerHTML = `
    <h2 class="page-title">${isAdmin() ? "Files & Policies" : "My Access"}</h2>
    ${isAdmin() ? `
    <div class="card">
      <h3>Upload &amp; Classify a File</h3>
      <form id="upload-form">
        <div class="form-row">
          <input type="file" id="upload-file" required />
          <select id="upload-class">
            <option value="PUBLIC">PUBLIC</option>
            <option value="INTERNAL">INTERNAL</option>
            <option value="CONFIDENTIAL" selected>CONFIDENTIAL</option>
            <option value="HIGHLY_CONFIDENTIAL">HIGHLY_CONFIDENTIAL</option>
          </select>
          <button type="submit" style="flex:0 0 auto">Encrypt &amp; Store</button>
        </div>
      </form>
      <div class="error-msg" id="upload-error"></div>
    </div>` : ""}
    <div class="card">
      <h3>Resources</h3>
      <p class="muted" style="margin-top:0">Every action is decided by the policy engine — including for administrators. HIGHLY_CONFIDENTIAL data needs an MFA-verified session.</p>
      <div id="files-table"></div>
    </div>
    <div id="decision-area"></div>`;

  if (isAdmin()) {
    document.getElementById("upload-form").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const fileInput = document.getElementById("upload-file");
      const errEl = document.getElementById("upload-error");
      errEl.textContent = "";
      if (!fileInput.files[0]) return;
      const fd = new FormData();
      fd.append("classification", document.getElementById("upload-class").value); // must precede the file
      fd.append("file", fileInput.files[0]);
      try { await API.call("POST", "/api/files/upload", fd, true); render(); }
      catch (e) { errEl.textContent = e.message; }
    });
  }
  renderFilesTable(files, policies);
}

function renderFilesTable(files, policies) {
  const el = document.getElementById("files-table");
  if (files.length === 0) { el.innerHTML = `<p class="muted">No files available.</p>`; return; }
  el.innerHTML = `
    <table>
      <thead><tr><th>Name</th><th>Classification</th><th>Size</th><th>Uploaded</th>${isAdmin() ? "<th>Policies</th>" : ""}<th>Actions</th></tr></thead>
      <tbody>
        ${files.map(f => `
          <tr>
            <td>${esc(f.name)}</td>
            <td><span class="tag ${esc(f.classification)}">${esc(f.classification.replace("_", " "))}</span></td>
            <td>${f.size} B</td>
            <td>${fmtDate(f.uploadedAt)}</td>
            ${isAdmin() ? `<td id="pol-${f.id}"></td>` : ""}
            <td>
              <button class="action-btn" onclick="attemptAccess('${f.id}','READ')">Read</button>
              <button class="secondary action-btn" onclick="attemptAccess('${f.id}','DOWNLOAD')">Download</button>
              <button class="danger action-btn" onclick="confirmDelete('${f.id}','${esc(f.name).replace(/'/g, "&#39;")}')">Delete</button>
            </td>
          </tr>`).join("")}
      </tbody>
    </table>`;
  if (isAdmin()) {
    files.forEach(f => {
      const cell = document.getElementById(`pol-${f.id}`);
      const fp = policies.filter(p => p.resourceId === f.id);
      cell.innerHTML = fp.map(p => `
        <span class="tag role">${esc(p.role)}: ${p.actions.map(esc).join("+")}</span>
        <a href="#" title="Revoke" onclick="revokePolicy('${p.id}');return false" style="color:var(--deny)">✕</a> `).join("")
        + `<button class="secondary action-btn" onclick="openPolicyForm('${f.id}')">+ Policy</button>`;
    });
  }
}

function openPolicyForm(fileId) {
  document.getElementById("decision-area").innerHTML = `
    <div class="card">
      <h3>Grant Policy for Resource</h3>
      <div class="form-row">
        <select id="policy-role">
          <option value="EMPLOYEE">EMPLOYEE</option>
          <option value="HR">HR</option>
          <option value="HR_MANAGER">HR_MANAGER</option>
          <option value="ADMIN">ADMIN</option>
        </select>
        <div class="checkbox-group">
          <label><input type="checkbox" value="READ" checked /> READ</label>
          <label><input type="checkbox" value="DOWNLOAD" /> DOWNLOAD</label>
          <label><input type="checkbox" value="DELETE" /> DELETE</label>
        </div>
        <button onclick="submitPolicy('${fileId}')" style="flex:0 0 auto">Save Policy</button>
      </div>
      <p class="muted">A policy only works within the role's clearance: EMPLOYEE ≤ INTERNAL, HR ≤ CONFIDENTIAL, HR_MANAGER/ADMIN ≤ HIGHLY_CONFIDENTIAL.</p>
      <div class="error-msg" id="policy-error"></div>
    </div>`;
}

async function submitPolicy(fileId) {
  const role = document.getElementById("policy-role").value;
  const actions = Array.from(document.querySelectorAll("#decision-area .checkbox-group input:checked")).map(i => i.value);
  const errEl = document.getElementById("policy-error");
  if (actions.length === 0) { errEl.textContent = "Select at least one action"; return; }
  try { await API.call("POST", "/api/policies", { resourceId: fileId, role, actions }); render(); }
  catch (e) { errEl.textContent = e.message; }
}

async function revokePolicy(id) {
  if (!confirm("Revoke this policy?")) return;
  try { await API.call("DELETE", `/api/policies/${id}`); render(); }
  catch (e) { alert(e.message); }
}

let lastBlob = null, lastName = "download";

function saveBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

function denyBanner(reason) {
  return `<div class="decision-banner DENY">⛔ DENY — ${esc(reason)}</div>`;
}

function confirmDelete(fileId, name) {
  if (!confirm(`Permanently delete "${name}"? (The request is still checked against policy.)`)) return;
  attemptAccess(fileId, "DELETE");
}

async function attemptAccess(fileId, action) {
  const area = document.getElementById("decision-area");
  area.innerHTML = `<p class="muted">Evaluating policy…</p>`;
  try {
    const res = await fetch(`/api/files/${fileId}/access`, {
      method: "POST", headers: API.headers(true), body: JSON.stringify({ action }),
    });
    const isJSON = (res.headers.get("Content-Type") || "").includes("application/json");
    if (!res.ok || isJSON) {
      const data = isJSON ? await res.json() : {};
      if (res.status === 401) { setToken(null); location.reload(); return; }
      if (!res.ok) { area.innerHTML = denyBanner(data.reason || data.error || res.statusText); return; }
      if (data.deleted) {   // DELETE succeeded — no file contents are ever returned
        area.innerHTML = `<div class="decision-banner ALLOW">✅ ALLOW — ${esc(data.reason)}</div>
          <div class="card"><h3>Deleted: ${esc(data.fileName)}</h3><p class="muted">The encrypted file and its policies were removed.</p></div>`;
        setTimeout(render, 1500);
        return;
      }
    }
    const reason = decodeURIComponent(res.headers.get("X-Vault-Reason") || "");
    const name = decodeURIComponent(res.headers.get("X-Vault-FileName") || "download");
    const truncated = res.headers.get("X-Vault-Truncated") === "true";
    const blob = await res.blob();
    lastBlob = blob; lastName = name;
    let preview = "(binary content — use Download)";
    try {
      const head = new Uint8Array(await blob.slice(0, 2000).arrayBuffer());
      const txt = new TextDecoder("utf-8", { fatal: true }).decode(head);
      if (!/[\x00-\x08\x0E-\x1F]/.test(txt)) preview = txt;
    } catch (e) { /* not text */ }
    area.innerHTML = `
      <div class="decision-banner ALLOW">✅ ALLOW — ${esc(reason)}</div>
      <div class="card">
        <h3>${esc(name)}</h3>
        <p class="muted">Decrypted and streamed for this request only; each chunk is integrity-checked before it is released.
          ${action === "READ" ? (truncated ? "READ returns a 64 KiB preview — use DOWNLOAD for the whole file." : "") : "Saved to your downloads."}</p>
        ${action === "READ" ? `<button onclick="saveBlob(lastBlob,lastName)">Save preview</button>` : ""}
        <pre style="white-space:pre-wrap;max-height:200px;overflow:auto;background:var(--panel-2);padding:10px;border-radius:6px;margin-top:12px;">${esc(preview)}</pre>
      </div>`;
    if (action === "DOWNLOAD") saveBlob(blob, name);
  } catch (e) {
    area.innerHTML = denyBanner(e.message);
  }
}

// ---- Users ----
async function renderUsers(main) {
  const users = await API.call("GET", "/api/users");
  main.innerHTML = `
    <h2 class="page-title">Users</h2>
    <div class="card">
      <h3>Create User</h3>
      <form id="user-form">
        <div class="form-row">
          <input id="new-username" placeholder="Username (3-64: letters, digits . _ -)" required />
          <input id="new-password" type="password" placeholder="Password (min 10, letter + digit)" required />
          <select id="new-role">
            <option value="EMPLOYEE">EMPLOYEE</option>
            <option value="HR">HR</option>
            <option value="HR_MANAGER">HR_MANAGER</option>
            <option value="ADMIN">ADMIN</option>
          </select>
          <button type="submit" style="flex:0 0 auto">Create</button>
        </div>
      </form>
      <div class="error-msg" id="user-error"></div>
    </div>
    <div class="card">
      <h3>All Users</h3>
      <table>
        <thead><tr><th>Username</th><th>Role</th><th>MFA</th><th>Created</th><th></th></tr></thead>
        <tbody>
          ${users.map(u => `<tr>
            <td>${esc(u.username)}</td>
            <td><span class="tag role">${esc(u.role)}</span></td>
            <td><span class="tag ${u.mfaEnabled ? "on" : "off"}">${u.mfaEnabled ? "enabled" : "off"}</span></td>
            <td>${fmtDate(u.createdAt)}</td>
            <td>${u.mfaEnabled ? `<button class="secondary action-btn" onclick="resetMfa('${u.id}','${esc(u.username)}')">Reset MFA</button>` : ""}</td>
          </tr>`).join("")}
        </tbody>
      </table>
    </div>`;
  document.getElementById("user-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const errEl = document.getElementById("user-error");
    try {
      await API.call("POST", "/api/users", {
        username: document.getElementById("new-username").value.trim(),
        password: document.getElementById("new-password").value,
        role: document.getElementById("new-role").value,
      });
      render();
    } catch (e) { errEl.textContent = e.message; }
  });
}

async function resetMfa(id, name) {
  if (!confirm(`Reset MFA for ${name}? Their sessions will be revoked and they must re-enrol.`)) return;
  try { await API.call("POST", `/api/users/${id}/mfa/reset`); render(); }
  catch (e) { alert(e.message); }
}

// ---- Audit ----
async function renderAudit(main) {
  const entries = await API.call("GET", "/api/audit?limit=200");
  main.innerHTML = `
    <h2 class="page-title">Audit Log</h2>
    <div class="card">
      <div class="form-row" style="align-items:center">
        <button id="verify-btn" style="flex:0 0 auto">Verify log integrity</button>
        <span class="muted">Checks the tamper-evident hash chain over the whole log.</span>
      </div>
      <div id="verify-result"></div>
    </div>
    <div class="card">${auditTable(entries)}</div>`;
  document.getElementById("verify-btn").onclick = async () => {
    const out = document.getElementById("verify-result");
    out.innerHTML = `<p class="muted">Verifying…</p>`;
    try {
      const v = await API.call("GET", "/api/audit/verify");
      out.innerHTML = v.ok
        ? `<div class="banner ok">✅ ${esc(v.message)} — ${v.checked} chained entries verified${v.legacyUnchained ? `, ${v.legacyUnchained} older entries pre-date the chain` : ""}.<br><span class="mono" style="font-size:12px">head: ${esc(v.headHash)}</span></div>`
        : `<div class="banner bad">⛔ ${esc(v.message)}<br>First bad entry: <span class="mono">${esc(v.brokenAtEntryId)}</span> (position ${v.brokenAtPosition}).</div>`;
    } catch (e) { out.innerHTML = `<p class="error-msg">${esc(e.message)}</p>`; }
  };
}

// ---- Security (MFA) ----
async function renderSecurity(main) {
  state.user = await API.call("GET", "/api/me");
  const u = state.user;
  main.innerHTML = `
    <h2 class="page-title">Security</h2>
    ${u.mfaSetupRequired ? `<div class="banner warn">Multi-factor authentication is mandatory on this server. Enrol below to continue.</div>` : ""}
    <div class="card">
      <h3>Multi-factor authentication (TOTP)</h3>
      <p>Status: <span class="tag ${u.mfaEnabled ? "on" : "off"}">${u.mfaEnabled ? "enabled" : "not enabled"}</span>
         &nbsp; This session: <span class="tag ${u.mfaVerified ? "on" : "off"}">${u.mfaVerified ? "MFA-verified" : "password only"}</span></p>
      <p class="muted">HIGHLY_CONFIDENTIAL files require an MFA-verified session, as does deleting CONFIDENTIAL files.</p>
      <div id="mfa-area"></div>
    </div>`;
  const area = document.getElementById("mfa-area");
  if (!u.mfaEnabled) {
    area.innerHTML = `<button id="mfa-start">Set up authenticator app</button><div class="error-msg" id="mfa-error" style="margin-top:10px"></div>`;
    document.getElementById("mfa-start").onclick = startMfaSetup;
  } else {
    area.innerHTML = `
      <h3 style="font-size:14px">Disable MFA</h3>
      <div class="form-row">
        <input id="dis-pass" type="password" placeholder="Current password" />
        <input id="dis-code" placeholder="Authenticator or recovery code" />
        <button class="danger" id="dis-btn" style="flex:0 0 auto">Disable</button>
      </div>
      <div class="error-msg" id="mfa-error"></div>`;
    document.getElementById("dis-btn").onclick = async () => {
      try {
        await API.call("POST", "/api/mfa/disable", { password: document.getElementById("dis-pass").value, code: document.getElementById("dis-code").value.trim() });
        render();
      } catch (e) { document.getElementById("mfa-error").textContent = e.message; }
    };
  }
}

async function startMfaSetup() {
  const area = document.getElementById("mfa-area");
  try {
    const s = await API.call("POST", "/api/mfa/setup");
    const grouped = s.secret.replace(/(.{4})/g, "$1 ").trim();
    area.innerHTML = `
      <ol>
        <li>In your authenticator app (Google Authenticator, Microsoft Authenticator, Authy, 1Password…) choose <b>Add account → Enter a setup key</b> (time-based).</li>
        <li>Enter this key: <div class="secret-box mono">${esc(grouped)}</div>
          <span class="muted">Or open on a phone: <a href="${esc(s.otpauthUri)}" style="color:var(--accent)">otpauth link</a></span></li>
        <li>Type the 6-digit code the app shows to confirm:</li>
      </ol>
      <div class="form-row">
        <input id="mfa-confirm" placeholder="123456" inputmode="numeric" maxlength="7" />
        <button id="mfa-enable" style="flex:0 0 auto">Confirm &amp; enable</button>
      </div>
      <div class="error-msg" id="mfa-error"></div>`;
    document.getElementById("mfa-enable").onclick = async () => {
      try {
        const r = await API.call("POST", "/api/mfa/enable", { code: document.getElementById("mfa-confirm").value.trim() });
        state.user = await API.call("GET", "/api/me");
        document.getElementById("mfa-area").innerHTML = `
          <div class="banner ok">✅ MFA is now enabled and this session is MFA-verified.</div>
          <h3 style="font-size:14px">Recovery codes — save them now</h3>
          <p class="muted">Each code works once if you lose your device. They will not be shown again.</p>
          <div class="codes-grid mono">${r.recoveryCodes.map(c => `<div>${esc(c)}</div>`).join("")}</div>
          <button class="secondary" onclick="navigator.clipboard.writeText('${r.recoveryCodes.join("\\n")}')">Copy codes</button>
          <button style="margin-left:8px" onclick="enterApp()">Continue</button>`;
      } catch (e) { document.getElementById("mfa-error").textContent = e.message; }
    };
  } catch (e) {
    const el = document.getElementById("mfa-error");
    if (el) el.textContent = e.message;
  }
}

tryResume();
