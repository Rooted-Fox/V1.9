const CATEGORY_INFO = {
  "A01:broken_access_control":          { code: "A01", label: "Broken access control" },
  "A02:security_misconfiguration":      { code: "A02", label: "Security misconfiguration" },
  "A03:software_supply_chain_failures": { code: "A03", label: "Supply chain failures" },
  "A04:cryptographic_failures":         { code: "A04", label: "Cryptographic failures" },
  "A05:injection":                      { code: "A05", label: "Injection" },
  "A06:insecure_design":                { code: "A06", label: "Insecure design" },
  "A07:authentication_failures":        { code: "A07", label: "Authentication failures" },
  "A08:software_data_integrity_failures": { code: "A08", label: "Integrity failures" },
  "A09:logging_alerting_failures":      { code: "A09", label: "Logging & alerting failures" },
  "A10:mishandling_exceptional_conditions": { code: "A10", label: "Exceptional conditions" },
};

async function api(path, options = {}) {
  const res = await fetch(`/api${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `Request failed (${res.status})`);
  }
  return res.status === 204 ? null : res.json();
}

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value == null ? "" : value;
  return div.innerHTML;
}

function showToast(message) {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 2400);
}

/* ---------- tabs ---------- */

function switchTab(name) {
  document.querySelectorAll(".tab").forEach((tab) => {
    const active = tab.dataset.tab === name;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
  });
  document.querySelectorAll(".panel").forEach((panel) => {
    const active = panel.id === `panel-${name}`;
    panel.classList.toggle("active", active);
    panel.hidden = !active;
  });
  if (name === "dashboard") loadDashboard();
  if (name === "scanning") loadPending();
  if (name === "settings") loadSettings();
}

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => switchTab(tab.dataset.tab));
});

/* ---------- dashboard ---------- */

let selectedApp = "";

async function populateAppSelector() {
  const apps = await api("/apps");
  const select = document.getElementById("appSelectDashboard");
  const current = select.value;
  select.innerHTML =
    '<option value="">All applications</option>' +
    apps.map((name) => `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`).join("");
  select.value = apps.includes(current) ? current : "";
}

function onAppChange(value) {
  selectedApp = value;
  document.getElementById("appSelectDashboard").value = value;
  loadDashboard();
  loadPending();
}

document.getElementById("appSelectDashboard").addEventListener("change", (e) => onAppChange(e.target.value));

async function loadDashboard() {
  await populateAppSelector();
  const qs = selectedApp ? `?app_name=${encodeURIComponent(selectedApp)}` : "";
  const [severity, category] = await Promise.all([
    api(`/summary/severity${qs}`),
    api(`/summary/category${qs}`),
  ]);
  renderMetrics(severity);
  renderCategories(category);
  loadFindings();
}

function renderMetrics(severity) {
  const items = [
    { label: "Critical", value: severity.critical || 0, cls: "critical" },
    { label: "High", value: severity.high || 0, cls: "high" },
    { label: "Medium", value: severity.medium || 0, cls: "medium" },
    { label: "Low + info", value: (severity.low || 0) + (severity.info || 0), cls: "" },
  ];
  document.getElementById("metricGrid").innerHTML = items
    .map(
      (item) => `
      <div class="metric-card">
        <p class="metric-label">${item.label}</p>
        <p class="metric-value ${item.cls}">${item.value}</p>
      </div>`
    )
    .join("");
}

function renderCategories(category) {
  const grid = document.getElementById("categoryGrid");
  grid.innerHTML = Object.entries(CATEGORY_INFO)
    .map(([key, info]) => {
      const count = category[key] || 0;
      return `
        <button class="category-card" data-category="${key}" type="button">
          <div class="category-row">
            <span class="category-code">${info.code}</span>
            <span class="dot ${count > 0 ? "critical" : "info"}"></span>
          </div>
          <p class="category-name">${info.label}</p>
          <p class="category-count">${count} open</p>
        </button>`;
    })
    .join("");

  grid.querySelectorAll(".category-card").forEach((card) => {
    card.addEventListener("click", () => {
      document.getElementById("categoryFilter").value = card.dataset.category;
      renderFindings();
      document.getElementById("findingsList").scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });
}

/* ---------- pending findings + AI triage approval ---------- */

async function loadPending() {
  const qs = selectedApp ? `?app_name=${encodeURIComponent(selectedApp)}` : "";
  const [data, settings] = await Promise.all([api(`/pending${qs}`), api("/settings")]);
  renderPendingCard(data, settings);
}

function normalizeRawSeverity(raw) {
  if (!raw) return "info";
  const lower = String(raw).toLowerCase();
  if (lower === "informational") return "info";
  return ["critical", "high", "medium", "low"].includes(lower) ? lower : "info";
}

function downloadPending(findings, appName, format) {
  let blob, filename;
  if (format === "csv") {
    const headers = ["id", "tool", "category", "title", "url", "app_name", "raw_severity", "description", "created_at"];
    const escapeCsv = (value) => `"${String(value ?? "").replace(/"/g, '""')}"`;
    const lines = [headers.join(","), ...findings.map((f) => headers.map((h) => escapeCsv(f[h])).join(","))];
    blob = new Blob([lines.join("\n")], { type: "text/csv" });
    filename = `pending-findings-${appName || "all"}.csv`;
  } else {
    blob = new Blob([JSON.stringify(findings, null, 2)], { type: "application/json" });
    filename = `pending-findings-${appName || "all"}.json`;
  }
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function renderPendingCard(data, settings) {
  const block = document.getElementById("pendingBlock");
  const card = document.getElementById("pendingCard");

  if (data.count === 0) {
    block.hidden = true;
    return;
  }
  block.hidden = false;

  const badges = Object.entries(data.by_category)
    .map(([key, count]) => {
      const info = CATEGORY_INFO[key] || { code: key };
      return `<span class="badge info">${info.code} &middot; ${count}</span>`;
    })
    .join(" ");

  const hasCreds =
    settings.provider === "azure_foundry" ? settings.azure_foundry_api_key_set : settings.anthropic_api_key_set;

  let disabled = false;
  let note = "";
  if (!settings.ai_enabled) {
    disabled = true;
    note = "AI integration is off. Turn it on in Settings whenever you actually want these reviewed - it's optional and can wait.";
  } else if (!hasCreds) {
    disabled = true;
    note = "Add your Anthropic API key (or Azure Foundry credentials) in Settings if/when you want these triaged with AI.";
  } else {
    note = "Optional - only spends tokens when you click this, and only for these findings.";
  }

  const rows = data.findings
    .map((f) => {
      const info = CATEGORY_INFO[f.category] || { code: "", label: f.category };
      const severity = normalizeRawSeverity(f.raw_severity);
      return `
        <div class="finding-row">
          <div class="finding-head" data-toggle>
            <div>
              <p class="finding-title">${escapeHtml(f.title)}</p>
              <p class="finding-meta">${info.code} &middot; ${escapeHtml(f.tool)} &middot; ${escapeHtml(f.url) || "n/a"}</p>
            </div>
            <span class="badge ${severity}">${escapeHtml(f.raw_severity) || "info"}</span>
          </div>
          <div class="finding-body">
            <div class="finding-field">
              <p class="finding-field-label">Description</p>
              <p class="finding-field-value">${escapeHtml(f.description) || "—"}</p>
            </div>
          </div>
        </div>`;
    })
    .join("");

  card.innerHTML = `
    <p class="finding-title">${data.count} finding${data.count === 1 ? "" : "s"} found</p>
    <p class="finding-meta" style="margin-bottom: 12px;">${badges}</p>
    <div class="finding-actions" style="margin-bottom: 16px;">
      <button class="ghost" type="button" id="downloadPendingJson">Download raw findings (JSON)</button>
      <button class="ghost" type="button" id="downloadPendingCsv">Download raw findings (CSV)</button>
    </div>
    <button class="primary" type="button" id="approveTriageButton" ${disabled ? "disabled" : ""}>Approve AI triage</button>
    <p class="form-note" id="triageNote" style="margin-top: 8px;">${note}</p>
    <div style="margin-top: 20px; display: flex; flex-direction: column; gap: 10px;">${rows}</div>
  `;

  document.getElementById("approveTriageButton").addEventListener("click", approveTriage);
  document.getElementById("downloadPendingJson").addEventListener("click", () => downloadPending(data.findings, selectedApp, "json"));
  document.getElementById("downloadPendingCsv").addEventListener("click", () => downloadPending(data.findings, selectedApp, "csv"));
  card.querySelectorAll(".finding-head").forEach((head) => {
    head.addEventListener("click", () => head.closest(".finding-row").classList.toggle("expanded"));
  });
}

async function approveTriage() {
  const note = document.getElementById("triageNote");
  note.textContent = "";
  try {
    await api("/triage", { method: "POST", body: JSON.stringify({ app_name: selectedApp || null }) });
    showToast("AI triage started");
    pollTriageStatus();
  } catch (err) {
    note.textContent = err.message;
  }
}

let triagePollHandle = null;

async function pollTriageStatus() {
  const s = await api("/triage/status");
  const button = document.getElementById("approveTriageButton");
  if (button) button.disabled = s.running;

  if (s.running) {
    if (!triagePollHandle) triagePollHandle = setInterval(pollTriageStatus, 2500);
  } else {
    if (triagePollHandle) {
      clearInterval(triagePollHandle);
      triagePollHandle = null;
    }
    if (s.last_error) showToast(s.last_error);
    loadPending();
    if (document.getElementById("panel-dashboard").classList.contains("active")) loadDashboard();
    if (document.getElementById("panel-settings").classList.contains("active")) loadTokenUsage();
  }
}

/* ---------- findings ---------- */

let allFindings = [];
let categoryFilterPopulated = false;

function populateCategoryFilter() {
  if (categoryFilterPopulated) return;
  const select = document.getElementById("categoryFilter");
  Object.entries(CATEGORY_INFO).forEach(([key, info]) => {
    const option = document.createElement("option");
    option.value = key;
    option.textContent = `${info.code} ${info.label}`;
    select.appendChild(option);
  });
  categoryFilterPopulated = true;
}

async function loadFindings() {
  populateCategoryFilter();
  const qs = selectedApp ? `?app_name=${encodeURIComponent(selectedApp)}` : "";
  allFindings = await api(`/findings${qs}`);
  renderFindings();
}

function renderFindings() {
  const severity = document.getElementById("severityFilter").value;
  const status = document.getElementById("statusFilter").value;
  const category = document.getElementById("categoryFilter").value;

  const filtered = allFindings.filter(
    (f) =>
      (!severity || f.severity === severity) &&
      (!status || f.status === status) &&
      (!category || f.category === category)
  );

  const list = document.getElementById("findingsList");

  if (filtered.length === 0) {
    list.innerHTML = `
      <div class="empty-state">
        <p>${allFindings.length === 0 ? "No findings yet." : "No findings match these filters."}</p>
        ${allFindings.length === 0 ? '<button class="ghost" type="button" id="emptyStateScanLink">Run a scan</button>' : ""}
      </div>`;
    const link = document.getElementById("emptyStateScanLink");
    if (link) link.addEventListener("click", () => switchTab("scanning"));
    return;
  }

  list.innerHTML = filtered
    .map((f) => {
      const info = CATEGORY_INFO[f.category] || { code: "", label: f.category };
      return `
        <div class="finding-row" data-id="${f.id}">
          <div class="finding-head" data-toggle>
            <div>
              <p class="finding-title">${escapeHtml(f.title)}</p>
              <p class="finding-meta">${escapeHtml(f.app_name)} &middot; ${info.code} &middot; ${escapeHtml(f.tool)} &middot; ${escapeHtml(f.url) || "n/a"}</p>
            </div>
            <span class="badge ${f.severity}">${f.severity}</span>
          </div>
          <div class="finding-body">
            <div class="finding-field">
              <p class="finding-field-label">Rationale</p>
              <p class="finding-field-value">${escapeHtml(f.rationale) || "—"}</p>
            </div>
            <div class="finding-field">
              <p class="finding-field-label">Remediation</p>
              <p class="finding-field-value">${escapeHtml(f.remediation) || "No fix needed."}</p>
            </div>
            <div class="finding-actions">
              <button class="ghost" type="button" data-status="in_review">Mark in review</button>
              <button class="ghost" type="button" data-status="patched">Mark patched</button>
              <button class="ghost" type="button" data-status="dismissed">Dismiss</button>
            </div>
          </div>
        </div>`;
    })
    .join("");

  list.querySelectorAll(".finding-head").forEach((head) => {
    head.addEventListener("click", () => head.closest(".finding-row").classList.toggle("expanded"));
  });

  list.querySelectorAll("[data-status]").forEach((button) => {
    button.addEventListener("click", async (event) => {
      event.stopPropagation();
      const row = button.closest(".finding-row");
      await api(`/findings/${row.dataset.id}`, {
        method: "PATCH",
        body: JSON.stringify({ status: button.dataset.status }),
      });
      showToast("Status updated");
      loadFindings();
    });
  });
}

["severityFilter", "statusFilter", "categoryFilter"].forEach((id) => {
  document.getElementById(id).addEventListener("change", renderFindings);
});

/* ---------- settings ---------- */

function applyProviderVisibility(provider) {
  document.getElementById("anthropicKeyField").hidden = provider === "azure_foundry";
  document.getElementById("azureEndpointField").hidden = provider !== "azure_foundry";
  document.getElementById("azureKeyField").hidden = provider !== "azure_foundry";
}

document.getElementById("providerSelect").addEventListener("change", (e) => applyProviderVisibility(e.target.value));

async function loadSettings() {
  const s = await api("/settings");
  document.getElementById("providerSelect").value = s.provider;
  applyProviderVisibility(s.provider);
  document.getElementById("aiEnabledToggle").checked = !!s.ai_enabled;
  document.getElementById("skipInfoToggle").checked = !!s.skip_info_findings;
  document.getElementById("apiKeyStatus").textContent = s.anthropic_api_key_set
    ? `Key saved (${s.anthropic_api_key_masked})`
    : "No key saved yet - add one to enable AI triage.";
  document.getElementById("azureEndpointInput").value = s.azure_foundry_endpoint || "";
  document.getElementById("azureKeyStatus").textContent = s.azure_foundry_api_key_set
    ? `Key saved (${s.azure_foundry_api_key_masked})`
    : "No key saved yet.";
  document.getElementById("modelInput").value = s.agent_model || "";
  document.getElementById("zapUrlInput").value = s.zap_api_url || "";
  document.getElementById("zapKeyStatus").textContent = s.zap_api_key_set ? "Key saved" : "No key saved yet.";
  document.getElementById("slackStatus").textContent = s.slack_webhook_url_set
    ? "Webhook saved"
    : "No webhook saved yet.";
  loadTokenUsage();
}

document.getElementById("settingsForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const body = {
    provider: document.getElementById("providerSelect").value,
    ai_enabled: document.getElementById("aiEnabledToggle").checked,
    anthropic_api_key: document.getElementById("apiKeyInput").value || null,
    azure_foundry_endpoint: document.getElementById("azureEndpointInput").value || null,
    azure_foundry_api_key: document.getElementById("azureKeyInput").value || null,
    agent_model: document.getElementById("modelInput").value || null,
    zap_api_url: document.getElementById("zapUrlInput").value || null,
    zap_api_key: document.getElementById("zapKeyInput").value || null,
    slack_webhook_url: document.getElementById("slackInput").value || null,
  };
  await api("/settings", { method: "POST", body: JSON.stringify(body) });
  document.getElementById("apiKeyInput").value = "";
  document.getElementById("azureKeyInput").value = "";
  document.getElementById("zapKeyInput").value = "";
  document.getElementById("slackInput").value = "";
  showToast("Settings saved");
  loadSettings();
  loadPending();
});

async function loadTokenUsage() {
  const data = await api("/tokens");
  document.getElementById("tokenLimitInput").value = data.limit || "";
  document.getElementById("tokenMetricGrid").innerHTML = [
    { label: "Used", value: data.used },
    { label: "Limit", value: data.limit || "Unlimited" },
    { label: "Remaining", value: data.remaining === null ? "—" : data.remaining },
  ]
    .map(
      (item) => `
      <div class="metric-card">
        <p class="metric-label">${item.label}</p>
        <p class="metric-value accent">${item.value}</p>
      </div>`
    )
    .join("");
}

document.getElementById("saveTokenLimitButton").addEventListener("click", async () => {
  const raw = document.getElementById("tokenLimitInput").value.trim();
  const value = raw === "" ? 0 : parseInt(raw, 10);
  if (Number.isNaN(value) || value < 0) {
    showToast("Enter a whole number, 0 or more");
    return;
  }
  await api("/settings", {
    method: "POST",
    body: JSON.stringify({
      token_limit: value,
      skip_info_findings: document.getElementById("skipInfoToggle").checked,
    }),
  });
  showToast("Cost settings saved");
  loadTokenUsage();
});

document.getElementById("resetTokensButton").addEventListener("click", async () => {
  if (!confirm("Reset token usage back to zero? This only resets the counter, not your budget limit.")) return;
  await api("/tokens/reset", { method: "POST" });
  showToast("Usage reset");
  loadTokenUsage();
});

/* ---------- scan trigger + status polling ---------- */

let pollHandle = null;

document.getElementById("scanForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const targetUrl = document.getElementById("targetUrlInput").value.trim();
  const appName = document.getElementById("appNameInput").value.trim();
  const errorEl = document.getElementById("scanError");
  errorEl.hidden = true;

  try {
    await api("/scan", {
      method: "POST",
      body: JSON.stringify({ target_url: targetUrl, app_name: appName || null }),
    });
    showToast("Scan started");
    pollStatus();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.hidden = false;
  }
});

async function pollStatus() {
  const s = await api("/scan/status");
  updateStatusUI(s);
  if (s.running) {
    if (!pollHandle) pollHandle = setInterval(pollStatus, 3000);
  } else {
    if (pollHandle) {
      clearInterval(pollHandle);
      pollHandle = null;
    }
    // show which tools ran vs were skipped
    if (s.scanner_log && s.scanner_log.length > 0) {
      const logEl = document.getElementById("scannerLog");
      if (logEl) {
        logEl.innerHTML = s.scanner_log.map(line =>
          `<p class="form-note" style="margin:2px 0; color:${line.includes('[error]') ? 'var(--critical)' : 'var(--text-tertiary)'};">${escapeHtml(line)}</p>`
        ).join("");
      }
    }
    loadPending();
    if (document.getElementById("panel-dashboard").classList.contains("active")) loadDashboard();
  }
}

function updateStatusUI(s) {
  const pill = document.getElementById("statusPill");
  const topbar = document.getElementById("topbar");
  const scanButton = document.getElementById("scanButton");
  topbar.classList.toggle("scanning", s.running);
  scanButton.disabled = s.running;

  if (s.running) {
    pill.textContent = `scanning ${s.app_name || s.target_url}`;
    pill.className = "status-pill running";
  } else if (s.last_error) {
    pill.textContent = "last scan failed";
    pill.className = "status-pill error";
    pill.title = s.last_error;
  } else if (s.last_raw_count !== null && s.last_raw_count !== undefined) {
    pill.textContent = `${s.app_name || ""}: ${s.last_raw_count} queued`.replace(/^: /, "");
    pill.className = "status-pill";
  } else {
    pill.textContent = "idle";
    pill.className = "status-pill";
  }
}

/* ---------- init ---------- */

loadDashboard();
loadPending();
pollStatus();
