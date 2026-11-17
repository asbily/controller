"use strict";

const state = {
  token: sessionStorage.getItem("asbily_controller_token") || "",
  user: null,
  needsBootstrap: false,
  providers: [],
  overview: null
};

// ==========================================
// Helpers
// ==========================================

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function showToast(message, type = "ok") {
  const banner = document.getElementById("toastBanner");
  if (!banner) return;
  banner.textContent = message;
  banner.className = `toast ${type === "err" ? "toast-err" : "toast-ok"}`;
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => {
    banner.className = "toast hidden";
  }, 5000);
}

async function apiFetch(path, options = {}) {
  const headers = {
    Accept: "application/json",
    ...(options.body ? { "Content-Type": "application/json" } : {}),
    ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}),
    ...(options.headers || {})
  };

  const response = await fetch(path, {
    ...options,
    headers
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const errMsg = data?.error?.message || data?.error || `HTTP ${response.status}`;
    throw new Error(errMsg);
  }
  return data;
}

// ==========================================
// Navigation
// ==========================================

function activateSection(sectionId) {
  const validId = document.getElementById(`section-${sectionId}`) ? sectionId : "overview";
  document.querySelectorAll(".panel-section").forEach((sec) => {
    sec.classList.toggle("active", sec.id === `section-${validId}`);
  });
  document.querySelectorAll(".nav-item").forEach((item) => {
    item.classList.toggle("active", item.dataset.section === validId);
  });

  const sidebar = document.getElementById("sidebar");
  const toggle = document.getElementById("sidebarToggle");
  if (sidebar && toggle) {
    sidebar.classList.remove("open");
    toggle.setAttribute("aria-expanded", "false");
  }

  if (window.location.hash !== `#${validId}`) {
    history.replaceState(null, "", `#${validId}`);
  }
}

function initNavigation() {
  const sidebarToggle = document.getElementById("sidebarToggle");
  const sidebar = document.getElementById("sidebar");

  if (sidebarToggle && sidebar) {
    sidebarToggle.addEventListener("click", () => {
      const open = sidebar.classList.toggle("open");
      sidebarToggle.setAttribute("aria-expanded", String(open));
    });
  }

  document.querySelectorAll("[data-section], [data-goto], [data-nav]").forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const target = link.dataset.section || link.dataset.goto || link.dataset.nav;
      if (target) activateSection(target);
    });
  });

  const initialHash = window.location.hash.replace(/^#/, "");
  activateSection(initialHash || "overview");
}

// ==========================================
// Renderers
// ==========================================

function renderOverview(data) {
  state.overview = data;
  state.needsBootstrap = Boolean(data.needsBootstrap);
  state.user = data.user || null;
  state.providers = data.providers || [];

  document.getElementById("metricTotalRequests").textContent = String(data.metrics.totalRequests);
  document.getElementById("metricSuccessRequests").textContent = String(data.metrics.successfulRequests);
  document.getElementById("metricFailedRequests").textContent = String(data.metrics.failedRequests);
  document.getElementById("metricActiveBackend").textContent = data.activeProvider
    ? `${data.activeProvider.name}`
    : "None";
  document.getElementById("metricApiHealth").textContent = data.apiHealth.status.toUpperCase();

  const activeTest = data.activeProvider?.lastTest;
  const backendHealthText = !data.activeProvider?.backendUrl
    ? "URL Needed"
    : activeTest
      ? activeTest.ok
        ? `Online (${activeTest.latencyMs}ms)`
        : `Error (${activeTest.status})`
      : "Untested";
  document.getElementById("metricBackendHealth").textContent = backendHealthText;

  document.getElementById("activeProviderBadge").textContent = data.activeProvider
    ? `Active: ${data.activeProvider.type.toUpperCase()}`
    : "Active: None";
  document.getElementById("runtimeLabel").textContent = data.apiHealth.runtime;

  // Auth status badge
  const authBadge = document.getElementById("authStatusBadge");
  const topAuthBtn = document.getElementById("topAuthBtn");
  if (state.user) {
    authBadge.textContent = `${state.user.email} (${state.user.role})`;
    authBadge.className = "badge badge-ok";
    topAuthBtn.textContent = "Account";
  } else {
    authBadge.textContent = state.needsBootstrap ? "Setup Required" : "Guest (Read-Only)";
    authBadge.className = "badge";
    topAuthBtn.textContent = state.needsBootstrap ? "Setup Admin" : "Sign In";
  }

  // Overview providers
  const ovProv = document.getElementById("overviewProviderList");
  ovProv.replaceChildren();
  for (const p of state.providers) {
    const row = el("div", "stack-row");
    const left = el("div");
    left.append(el("strong", "", p.name));
    left.append(el("div", "provider-meta", p.backendUrl || "No URL configured"));

    const statusBadge = el(
      "span",
      `badge ${p.lastTest?.ok ? "badge-ok" : p.backendUrl ? "" : "badge-err"}`,
      !p.enabled
        ? "Disabled"
        : !p.backendUrl
          ? "Unconfigured"
          : p.lastTest
            ? p.lastTest.ok
              ? `Healthy ${p.lastTest.latencyMs}ms`
              : `HTTP ${p.lastTest.status}`
            : "Configured"
    );
    row.append(left, statusBadge);
    ovProv.append(row);
  }

  // Overview activity
  const ovAct = document.getElementById("overviewActivityList");
  ovAct.replaceChildren();
  if (!data.recentActivity || data.recentActivity.length === 0) {
    ovAct.append(el("div", "muted-text", "No recent activity yet."));
  } else {
    for (const item of data.recentActivity) {
      const row = el("div", "stack-row");
      const left = el("div");
      left.append(el("div", "mono", item.summary));
      left.append(el("div", "provider-meta", `${item.actor} • ${new Date(item.timestamp).toLocaleTimeString()}`));
      row.append(left, el("span", "badge", item.outcome));
      ovAct.append(row);
    }
  }

  renderAuthSection();
  renderProvidersSection();
  populateDispatchProviders();
}

function renderAuthSection() {
  const details = document.getElementById("authSessionDetails");
  const signOutRow = document.getElementById("signOutRow");
  const bootstrapCard = document.getElementById("bootstrapCard");
  const loginCard = document.getElementById("loginCard");

  if (state.user) {
    details.textContent = `Signed in as ${state.user.name} (${state.user.email}) with role ${state.user.role}.`;
    signOutRow.classList.remove("hidden");
  } else {
    details.textContent = state.needsBootstrap
      ? "No administrator account has been created yet. Bootstrap the first super_admin below."
      : "Not signed in. Sign in to modify providers, environment secrets, routes, or users.";
    signOutRow.classList.add("hidden");
  }

  bootstrapCard.classList.toggle("hidden", !state.needsBootstrap);
  loginCard.classList.toggle("hidden", state.needsBootstrap);
}

function populateDispatchProviders() {
  const select = document.getElementById("dispatchProvider");
  if (!select) return;
  const current = select.value;
  select.replaceChildren(el("option", "", "Auto (Active / Rule)"));
  select.firstChild.value = "auto";

  for (const p of state.providers) {
    const opt = el("option", "", `${p.name} (${p.type})`);
    opt.value = p.id;
    select.append(opt);
  }
  if (current) select.value = current;
}

function renderProvidersSection() {
  const grid = document.getElementById("providersGrid");
  grid.replaceChildren();

  for (const p of state.providers) {
    const card = el("article", "provider-card");

    const top = el("div", "provider-top");
    const titleWrap = el("div");
    titleWrap.append(el("h3", "", p.name));
    titleWrap.append(el("div", "provider-meta mono", p.backendUrl || "No Backend URL configured"));

    const badges = el("div", "provider-badges");
    badges.append(el("span", "badge", p.type.toUpperCase()));
    if (p.isActive) badges.append(el("span", "badge badge-dark", "ACTIVE"));
    if (p.isDefault) badges.append(el("span", "badge", "DEFAULT"));
    badges.append(el("span", `badge ${p.enabled ? "badge-ok" : "badge-err"}`, p.enabled ? "Enabled" : "Disabled"));

    top.append(titleWrap, badges);
    card.append(top);

    const credsInfo = el(
      "div",
      "provider-meta",
      `Health: ${p.healthPath} | Timeout: ${p.timeoutMs}ms | Key: ${p.credentials.hasApiKey ? p.credentials.apiKeyMask : "None"} | Secret: ${p.credentials.hasApiSecret ? p.credentials.apiSecretMask : "None"}`
    );
    card.append(credsInfo);

    if (p.lastTest) {
      const testBox = el(
        "div",
        "stack-row",
        ""
      );
      const testText = el(
        "span",
        "mono",
        p.lastTest.ok
          ? `Last Test: HTTP ${p.lastTest.status} (${p.lastTest.latencyMs}ms)`
          : `Last Test Failed: ${p.lastTest.error}`
      );
      testBox.append(testText);
      card.append(testBox);
    }

    const actions = el("div", "provider-actions");

    const testBtn = el("button", "btn btn-sm btn-primary", "Test Connection");
    testBtn.type = "button";
    testBtn.addEventListener("click", () => handleTestProvider(p.id));

    const activeBtn = el("button", "btn btn-sm btn-secondary", "Set Active");
    activeBtn.type = "button";
    activeBtn.disabled = p.isActive;
    activeBtn.addEventListener("click", () => handlePatchProvider(p.id, { isActive: true }));

    const defaultBtn = el("button", "btn btn-sm btn-secondary", "Set Default");
    defaultBtn.type = "button";
    defaultBtn.disabled = p.isDefault;
    defaultBtn.addEventListener("click", () => handlePatchProvider(p.id, { isDefault: true }));

    const toggleBtn = el("button", "btn btn-sm btn-secondary", p.enabled ? "Disable" : "Enable");
    toggleBtn.type = "button";
    toggleBtn.addEventListener("click", () => handlePatchProvider(p.id, { enabled: !p.enabled }));

    const editBtn = el("button", "btn btn-sm btn-secondary", "Edit");
    editBtn.type = "button";
    editBtn.addEventListener("click", () => openProviderEditor(p));

    const delBtn = el("button", "btn btn-sm btn-danger", "Delete");
    delBtn.type = "button";
    delBtn.addEventListener("click", () => handleDeleteProvider(p.id));

    actions.append(testBtn, activeBtn, defaultBtn, toggleBtn, editBtn, delBtn);
    card.append(actions);
    grid.append(card);
  }
}

function openProviderEditor(provider = null) {
  const card = document.getElementById("providerFormCard");
  const title = document.getElementById("providerFormTitle");
  card.classList.remove("hidden");

  if (provider) {
    title.textContent = `Edit Provider: ${provider.name}`;
    document.getElementById("provId").value = provider.id;
    document.getElementById("provName").value = provider.name;
    document.getElementById("provType").value = provider.type;
    document.getElementById("provUrl").value = provider.backendUrl || "";
    document.getElementById("provHealthPath").value = provider.healthPath || "/health";
    document.getElementById("provTimeout").value = provider.timeoutMs || 8000;
    document.getElementById("provRoutes").value = (provider.routes || ["/api/v1/*"]).join(", ");
    document.getElementById("provHeaders").value = Object.keys(provider.customHeaders || {}).length
      ? JSON.stringify(provider.customHeaders)
      : "";
    document.getElementById("provEnabled").checked = Boolean(provider.enabled);
    document.getElementById("provActive").checked = Boolean(provider.isActive);
    document.getElementById("provDefault").checked = Boolean(provider.isDefault);
  } else {
    title.textContent = "Add Backend Provider";
    document.getElementById("providerForm").reset();
    document.getElementById("provId").value = "";
    document.getElementById("provHealthPath").value = "/health";
    document.getElementById("provTimeout").value = "8000";
    document.getElementById("provRoutes").value = "/api/v1/*";
    document.getElementById("provEnabled").checked = true;
  }

  document.getElementById("provApiKey").value = "";
  document.getElementById("provApiSecret").value = "";
  document.getElementById("provApiToken").value = "";
}

async function handleTestProvider(id) {
  try {
    const res = await apiFetch(`/api/controller/providers/${id}/test`, { method: "POST" });
    const t = res.testResult;
    showToast(
      t.ok
        ? `Connection succeeded: HTTP ${t.status} in ${t.latencyMs}ms`
        : `Connection failed: ${t.error}`,
      t.ok ? "ok" : "err"
    );
    await loadAllData();
  } catch (err) {
    showToast(err.message, "err");
  }
}

async function handlePatchProvider(id, patch) {
  try {
    await apiFetch(`/api/controller/providers/${id}`, {
      method: "PATCH",
      body: JSON.stringify(patch)
    });
    showToast("Provider configuration updated.");
    await loadAllData();
  } catch (err) {
    showToast(err.message, "err");
  }
}

async function handleDeleteProvider(id) {
  try {
    await apiFetch(`/api/controller/providers/${id}`, { method: "DELETE" });
    showToast("Provider deleted.");
    await loadAllData();
  } catch (err) {
    showToast(err.message, "err");
  }
}

async function loadEnvSection() {
  const data = await apiFetch("/api/controller/env");
  const vaultBody = document.getElementById("vaultEnvTableBody");
  vaultBody.replaceChildren();

  if (data.vaultVars.length === 0) {
    const tr = el("tr");
    const td = el("td", "muted-text", "No vault variables stored yet.");
    td.colSpan = 6;
    tr.append(td);
    vaultBody.append(tr);
  } else {
    for (const v of data.vaultVars) {
      const tr = el("tr");
      tr.append(el("td", "", v.scope));
      tr.append(el("td", "mono", v.key));
      tr.append(el("td", "mono", v.valuePreview || "—"));
      tr.append(el("td", "", v.isSecret ? "Secret" : "Plain"));
      tr.append(el("td", "", new Date(v.updatedAt).toLocaleString()));
      const actTd = el("td");
      const delBtn = el("button", "btn btn-sm btn-danger", "Delete");
      delBtn.type = "button";
      delBtn.addEventListener("click", async () => {
        try {
          await apiFetch(`/api/controller/env/${v.id}`, { method: "DELETE" });
          showToast(`Removed ${v.key}`);
          await loadEnvSection();
        } catch (err) {
          showToast(err.message, "err");
        }
      });
      actTd.append(delBtn);
      tr.append(actTd);
      vaultBody.append(tr);
    }
  }

  const procBody = document.getElementById("processEnvTableBody");
  procBody.replaceChildren();
  for (const e of data.environmentVars) {
    const tr = el("tr");
    tr.append(el("td", "", e.scope));
    tr.append(el("td", "mono", e.key));
    tr.append(el("td", "mono", e.configured ? e.valuePreview : "—"));
    const statusTd = el("td");
    statusTd.append(
      el("span", `badge ${e.configured ? "badge-ok" : ""}`, e.configured ? "Configured" : "Unset")
    );
    tr.append(statusTd);
    procBody.append(tr);
  }
}

async function loadRoutesSection() {
  const data = await apiFetch("/api/controller/routes");
  const tbody = document.getElementById("routesTableBody");
  tbody.replaceChildren();

  for (const r of data.routes) {
    const tr = el("tr");
    tr.append(el("td", "mono", r.pattern));
    tr.append(el("td", "", r.targetProvider));
    tr.append(el("td", "", r.authRequired ? "Required" : "Public"));
    tr.append(el("td", "", String(r.rateLimitPerMin)));
    tr.append(el("td", "", `${r.timeoutMs}ms`));
    tr.append(el("td", "", r.allowSafeFallback ? "GET/HEAD/OPT" : "Disabled"));
    tr.append(el("td", "", r.enabled ? "Enabled" : "Disabled"));

    const actTd = el("td");
    const toggleBtn = el("button", "btn btn-sm btn-secondary", r.enabled ? "Disable" : "Enable");
    toggleBtn.type = "button";
    toggleBtn.addEventListener("click", async () => {
      try {
        await apiFetch(`/api/controller/routes/${r.id}`, {
          method: "PATCH",
          body: JSON.stringify({ enabled: !r.enabled })
        });
        await loadRoutesSection();
      } catch (err) {
        showToast(err.message, "err");
      }
    });
    actTd.append(toggleBtn);
    tr.append(actTd);
    tbody.append(tr);
  }
}

async function loadUsersSection() {
  const tbody = document.getElementById("usersTableBody");
  tbody.replaceChildren();

  if (!state.user) {
    const tr = el("tr");
    const td = el("td", "muted-text", "Sign in to view and manage registered controller users.");
    td.colSpan = 6;
    tr.append(td);
    tbody.append(tr);
    return;
  }

  try {
    const data = await apiFetch("/api/v1/users");
    for (const u of data.users) {
      const tr = el("tr");
      tr.append(el("td", "", u.name));
      tr.append(el("td", "mono", u.email));
      tr.append(el("td", "", u.role));
      tr.append(el("td", "", u.status));
      tr.append(el("td", "", u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString() : "Never"));
      const actTd = el("td");
      if (u.id !== state.user.id) {
        const toggleBtn = el(
          "button",
          "btn btn-sm btn-secondary",
          u.status === "active" ? "Disable" : "Activate"
        );
        toggleBtn.type = "button";
        toggleBtn.addEventListener("click", async () => {
          try {
            await apiFetch(`/api/v1/users/${u.id}`, {
              method: "PATCH",
              body: JSON.stringify({ status: u.status === "active" ? "disabled" : "active" })
            });
            await loadUsersSection();
          } catch (err) {
            showToast(err.message, "err");
          }
        });
        actTd.append(toggleBtn);
      } else {
        actTd.append(el("span", "badge", "You"));
      }
      tr.append(actTd);
      tbody.append(tr);
    }
  } catch (err) {
    const tr = el("tr");
    const td = el("td", "muted-text", err.message);
    td.colSpan = 6;
    tr.append(td);
    tbody.append(tr);
  }
}

async function loadInfrastructureSections() {
  const [dbRes, fbRes, stRes, payRes, secRes, logsRes, monRes, setRes] = await Promise.all([
    apiFetch("/api/controller/database"),
    apiFetch("/api/controller/firebase"),
    apiFetch("/api/v1/storage"),
    apiFetch("/api/v1/payments"),
    apiFetch("/api/v1/security"),
    apiFetch("/api/controller/logs"),
    apiFetch("/api/controller/monitoring"),
    apiFetch("/api/controller/settings")
  ]);

  // Gateway Info
  const gwGrid = document.getElementById("gatewayInfoGrid");
  gwGrid.replaceChildren();
  const s = setRes.settings;
  [
    ["Gateway Mode", s.gatewayMode],
    ["Gateway URL", s.cloudflareGatewayUrl || "Local / Relative"],
    ["Default Timeout", `${s.defaultTimeoutMs}ms`],
    ["Rate Limit", `${s.rateLimitPerMin} req/min`],
    ["Idempotent Fallback", s.safeIdempotentFallbackOnly ? "Enabled (GET/HEAD/OPTIONS)" : "Disabled"],
    ["Maintenance Mode", s.maintenanceMode ? "ACTIVE" : "Off"]
  ].forEach(([k, v]) => {
    const card = el("div", "stat-card");
    card.append(el("span", "stat-label", k));
    card.append(el("div", "mono", v));
    gwGrid.append(card);
  });

  // Settings form values
  document.getElementById("setCfGatewayUrl").value = s.cloudflareGatewayUrl || "";
  document.getElementById("setTimeoutMs").value = s.defaultTimeoutMs || 8000;
  document.getElementById("setRateLimit").value = s.rateLimitPerMin || 120;
  document.getElementById("setIdempotentFallback").checked = Boolean(s.safeIdempotentFallbackOnly);
  document.getElementById("setStrictCors").checked = Boolean(s.strictCors);
  document.getElementById("setMaintenance").checked = Boolean(s.maintenanceMode);

  // Database
  const dbList = document.getElementById("databaseList");
  dbList.replaceChildren();
  for (const conn of dbRes.connections) {
    const row = el("div", "stack-row");
    const left = el("div");
    left.append(el("strong", "", conn.name));
    left.append(el("div", "provider-meta mono", `${conn.envKey}: ${conn.maskedUri || "Unconfigured"}`));
    row.append(left, el("span", `badge ${conn.configured ? "badge-ok" : ""}`, conn.status));
    dbList.append(row);
  }

  // Firebase
  const fbBody = document.getElementById("firebaseTableBody");
  fbBody.replaceChildren();
  for (const f of fbRes.fields) {
    const tr = el("tr");
    tr.append(el("td", "mono", f.key));
    const stTd = el("td");
    stTd.append(el("span", `badge ${f.configured ? "badge-ok" : ""}`, f.configured ? "Configured" : "Unset"));
    tr.append(stTd);
    tr.append(el("td", "mono", f.valuePreview || "—"));
    fbBody.append(tr);
  }

  // Storage (R2)
  const stList = document.getElementById("storageDetails");
  stList.replaceChildren();
  [
    ["Provider", "Cloudflare R2 (Future Storage Binding: ASBILY_STORAGE)"],
    ["Status", stRes.status],
    ["Bucket Name", stRes.configured.bucketName || "Not configured"],
    ["Endpoint", stRes.configured.endpoint || "Not configured"],
    ["Credentials", stRes.configured.accessKeyId && stRes.configured.secretAccessKey ? "Configured (Masked)" : "Not configured"]
  ].forEach(([label, val]) => {
    const row = el("div", "stack-row");
    row.append(el("strong", "", label), el("span", "mono", val));
    stList.append(row);
  });

  // Payments (Lemon Squeezy)
  const payList = document.getElementById("paymentsDetails");
  payList.replaceChildren();
  [
    ["Provider", "Lemon Squeezy"],
    ["Webhook Endpoint", payRes.webhookEndpoint],
    ["API Key", payRes.configured.apiKey ? "Configured (Masked)" : "Unset"],
    ["Webhook Secret", payRes.configured.webhookSecret ? "Configured (Masked)" : "Unset"],
    ["Store ID", payRes.configured.storeId ? "Configured" : "Unset"],
    ["Supported Events", `${payRes.allowedEvents.length} webhook event types`]
  ].forEach(([label, val]) => {
    const row = el("div", "stack-row");
    row.append(el("strong", "", label), el("span", "mono", val));
    payList.append(row);
  });

  // Security Policies
  const secList = document.getElementById("securityPoliciesList");
  secList.replaceChildren();
  for (const [k, v] of Object.entries(secRes.policies)) {
    const row = el("div", "stack-row");
    row.append(el("strong", "", k), el("span", "mono", Array.isArray(v) ? v.join(", ") : String(v)));
    secList.append(row);
  }

  // Logs
  const reqBody = document.getElementById("requestLogsBody");
  reqBody.replaceChildren();
  for (const log of logsRes.requestLogs.slice(0, 40)) {
    const tr = el("tr");
    tr.append(el("td", "", new Date(log.timestamp).toLocaleTimeString()));
    tr.append(el("td", "mono", log.method));
    tr.append(el("td", "mono", log.path));
    tr.append(el("td", "", String(log.status)));
    tr.append(el("td", "", `${log.latencyMs}ms`));
    tr.append(el("td", "", log.provider));
    reqBody.append(tr);
  }

  const audBody = document.getElementById("auditLogsBody");
  audBody.replaceChildren();
  for (const aud of logsRes.auditLogs.slice(0, 40)) {
    const tr = el("tr");
    tr.append(el("td", "", new Date(aud.timestamp).toLocaleTimeString()));
    tr.append(el("td", "mono", aud.actorEmail));
    tr.append(el("td", "", aud.actorRole));
    tr.append(el("td", "mono", aud.action));
    tr.append(el("td", "mono", aud.target));
    tr.append(el("td", "", aud.outcome));
    audBody.append(tr);
  }

  // Monitoring
  const monGrid = document.getElementById("monitoringStatsGrid");
  monGrid.replaceChildren();
  const m = monRes.monitoring;
  [
    ["Uptime", `${m.uptimeSeconds}s`],
    ["Memory RSS", `${m.memoryRssMb} MB`],
    ["Success Rate", `${m.successRate}%`],
    ["Avg Latency", `${m.avgLatencyMs}ms`],
    ["Total Requests", String(m.totalRequests)],
    ["Runtime", m.nodeVersion]
  ].forEach(([label, val]) => {
    const card = el("div", "stat-card");
    card.append(el("span", "stat-label", label));
    card.append(el("strong", "stat-value", val));
    monGrid.append(card);
  });

  const monProv = document.getElementById("monitoringProviderList");
  monProv.replaceChildren();
  for (const p of m.providerStatuses) {
    const row = el("div", "stack-row");
    row.append(
      el("strong", "", `${p.name} (${p.type})`),
      el(
        "span",
        `badge ${p.lastTest?.ok ? "badge-ok" : ""}`,
        p.lastTest ? (p.lastTest.ok ? `OK (${p.lastTest.latencyMs}ms)` : `Fail (${p.lastTest.status})`) : "Not Tested"
      )
    );
    monProv.append(row);
  }
}

async function loadAllData() {
  try {
    const overview = await apiFetch("/api/controller/overview");
    renderOverview(overview);
    await Promise.all([
      loadEnvSection(),
      loadRoutesSection(),
      loadUsersSection(),
      loadInfrastructureSections()
    ]);
  } catch (err) {
    showToast(`Failed to refresh controller data: ${err.message}`, "err");
  }
}

// ==========================================
// Form Listeners
// ==========================================

function bindForms() {
  document.getElementById("refreshAllBtn").addEventListener("click", loadAllData);

  document.getElementById("openNewProviderBtn").addEventListener("click", () => {
    openProviderEditor(null);
  });

  document.getElementById("cancelProviderFormBtn").addEventListener("click", () => {
    document.getElementById("providerFormCard").classList.add("hidden");
  });

  document.getElementById("providerForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const id = document.getElementById("provId").value;

    let customHeaders = {};
    const rawHeaders = document.getElementById("provHeaders").value.trim();
    if (rawHeaders) {
      try {
        customHeaders = JSON.parse(rawHeaders);
      } catch {
        showToast("Custom Headers must be valid JSON.", "err");
        return;
      }
    }

    const payload = {
      name: document.getElementById("provName").value.trim(),
      type: document.getElementById("provType").value,
      backendUrl: document.getElementById("provUrl").value.trim(),
      healthPath: document.getElementById("provHealthPath").value.trim() || "/health",
      timeoutMs: Number(document.getElementById("provTimeout").value) || 8000,
      routes: document
        .getElementById("provRoutes")
        .value.split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      customHeaders,
      enabled: document.getElementById("provEnabled").checked,
      isActive: document.getElementById("provActive").checked,
      isDefault: document.getElementById("provDefault").checked
    };

    const apiKey = document.getElementById("provApiKey").value.trim();
    const apiSecret = document.getElementById("provApiSecret").value.trim();
    const apiToken = document.getElementById("provApiToken").value.trim();
    if (apiKey) payload.apiKey = apiKey;
    if (apiSecret) payload.apiSecret = apiSecret;
    if (apiToken) payload.apiToken = apiToken;

    try {
      if (id) {
        await apiFetch(`/api/controller/providers/${id}`, {
          method: "PATCH",
          body: JSON.stringify(payload)
        });
        showToast("Backend provider updated.");
      } else {
        await apiFetch("/api/controller/providers", {
          method: "POST",
          body: JSON.stringify(payload)
        });
        showToast("Backend provider added.");
      }
      document.getElementById("providerFormCard").classList.add("hidden");
      await loadAllData();
    } catch (err) {
      showToast(err.message, "err");
    }
  });

  document.getElementById("envForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await apiFetch("/api/controller/env", {
        method: "POST",
        body: JSON.stringify({
          scope: document.getElementById("envScope").value,
          key: document.getElementById("envKey").value.trim().toUpperCase(),
          value: document.getElementById("envValue").value,
          isSecret: document.getElementById("envIsSecret").checked
        })
      });
      document.getElementById("envForm").reset();
      document.getElementById("envIsSecret").checked = true;
      showToast("Environment variable saved securely.");
      await loadEnvSection();
    } catch (err) {
      showToast(err.message, "err");
    }
  });

  document.getElementById("routeForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await apiFetch("/api/controller/routes", {
        method: "POST",
        body: JSON.stringify({
          pattern: document.getElementById("routePattern").value.trim(),
          service: document.getElementById("routeService").value.trim(),
          targetProvider: document.getElementById("routeTarget").value,
          rateLimitPerMin: Number(document.getElementById("routeRate").value) || 60,
          authRequired: document.getElementById("routeAuth").checked,
          allowSafeFallback: document.getElementById("routeFallback").checked
        })
      });
      document.getElementById("routeForm").reset();
      showToast("API route rule created.");
      await loadRoutesSection();
    } catch (err) {
      showToast(err.message, "err");
    }
  });

  document.getElementById("gatewayDispatchForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const out = document.getElementById("gatewayDispatchOutput");
    let payloadObj = undefined;
    const rawPayload = document.getElementById("dispatchPayload").value.trim();
    if (rawPayload) {
      try {
        payloadObj = JSON.parse(rawPayload);
      } catch {
        showToast("Gateway payload must be valid JSON.", "err");
        return;
      }
    }

    try {
      const res = await apiFetch("/api/controller/gateway/dispatch", {
        method: "POST",
        body: JSON.stringify({
          method: document.getElementById("dispatchMethod").value,
          path: document.getElementById("dispatchPath").value.trim(),
          providerId: document.getElementById("dispatchProvider").value,
          payload: payloadObj
        })
      });
      out.textContent = JSON.stringify(res.dispatch, null, 2);
      out.classList.remove("hidden");
      await loadAllData();
    } catch (err) {
      out.textContent = `Error: ${err.message}`;
      out.classList.remove("hidden");
      showToast(err.message, "err");
    }
  });

  document.getElementById("bootstrapForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const res = await apiFetch("/api/v1/auth/bootstrap", {
        method: "POST",
        body: JSON.stringify({
          name: document.getElementById("bootName").value.trim(),
          email: document.getElementById("bootEmail").value.trim(),
          password: document.getElementById("bootPassword").value
        })
      });
      state.token = res.token;
      sessionStorage.setItem("asbily_controller_token", res.token);
      showToast("Administrator account created and signed in.");
      await loadAllData();
    } catch (err) {
      showToast(err.message, "err");
    }
  });

  document.getElementById("loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const res = await apiFetch("/api/v1/auth/login", {
        method: "POST",
        body: JSON.stringify({
          email: document.getElementById("loginEmail").value.trim(),
          password: document.getElementById("loginPassword").value
        })
      });
      state.token = res.token;
      sessionStorage.setItem("asbily_controller_token", res.token);
      document.getElementById("loginForm").reset();
      showToast("Signed in successfully.");
      await loadAllData();
    } catch (err) {
      showToast(err.message, "err");
    }
  });

  document.getElementById("signOutBtn").addEventListener("click", async () => {
    await apiFetch("/api/v1/auth/logout", { method: "POST" }).catch(() => {});
    state.token = "";
    state.user = null;
    sessionStorage.removeItem("asbily_controller_token");
    showToast("Signed out.");
    await loadAllData();
  });

  document.getElementById("createUserForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await apiFetch("/api/v1/users", {
        method: "POST",
        body: JSON.stringify({
          name: document.getElementById("newUserName").value.trim(),
          email: document.getElementById("newUserEmail").value.trim(),
          role: document.getElementById("newUserRole").value,
          password: document.getElementById("newUserPass").value
        })
      });
      document.getElementById("createUserForm").reset();
      showToast("User created.");
      await loadUsersSection();
    } catch (err) {
      showToast(err.message, "err");
    }
  });

  document.getElementById("settingsForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await apiFetch("/api/controller/settings", {
        method: "PATCH",
        body: JSON.stringify({
          cloudflareGatewayUrl: document.getElementById("setCfGatewayUrl").value.trim(),
          defaultTimeoutMs: Number(document.getElementById("setTimeoutMs").value) || 8000,
          rateLimitPerMin: Number(document.getElementById("setRateLimit").value) || 120,
          safeIdempotentFallbackOnly: document.getElementById("setIdempotentFallback").checked,
          strictCors: document.getElementById("setStrictCors").checked,
          maintenanceMode: document.getElementById("setMaintenance").checked
        })
      });
      showToast("Controller settings saved.");
      await loadAllData();
    } catch (err) {
      showToast(err.message, "err");
    }
  });
}

// ==========================================
// Init
// ==========================================

document.addEventListener("DOMContentLoaded", () => {
  initNavigation();
  bindForms();
  loadAllData();
});
