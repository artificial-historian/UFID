const PAGE_LIMIT = 200;
const HASH_COLUMNS = ["crc32", "md5", "sha1", "sha256", "blake3"];
const DEFAULT_UFID_SOURCE_VALUE = "internet_archive";

const state = {
  user: null,
  activeTab: "alerts",
  loadingAlerts: false,
  loadingMatches: false,
  alerts: [],
  matches: [],
  alertsPage: 1,
  matchesPage: 1,
  alertsTotal: 0,
  matchesTotal: 0,
  alertsFilter: "",
  matchesFilter: "",
  alertsRequestId: 0,
  matchesRequestId: 0,
  clearingAlerts: false,
  matchesLoadingStartedAt: 0,
  sourceOptions: [],
  selectedSourceKeys: [],
  loadingSources: false,
  ufidSourceOptions: [],
  selectedUfidSources: [DEFAULT_UFID_SOURCE_VALUE],
  loadingUfidSources: false,
};

let alertsFilterTimer = null;
let matchesFilterTimer = null;
let matchesLoadingTimer = null;

const apiStatus = document.querySelector("#apiStatus");
const alertDescription = document.querySelector("#alertDescription");
const alertFilter = document.querySelector("#alertFilter");
const alertForm = document.querySelector("#alertForm");
const alertName = document.querySelector("#alertName");
const alertSize = document.querySelector("#alertSize");
const alertsNextButton = document.querySelector("#alertsNextButton");
const alertsPageInfo = document.querySelector("#alertsPageInfo");
const alertsPageNumberList = document.querySelector("#alertsPageNumberList");
const alertsPanel = document.querySelector("#alertsPanel");
const alertsPreviousButton = document.querySelector("#alertsPreviousButton");
const alertsSummary = document.querySelector("#alertsSummary");
const alertsTable = document.querySelector("#alertsTable");
const addAlertButton = document.querySelector("#addAlertButton");
const clearAlertsButton = document.querySelector("#clearAlertsButton");
const datFileInput = document.querySelector("#datFileInput");
const goldrushState = document.querySelector("#goldrushState");
const hashBlake3 = document.querySelector("#hashBlake3");
const hashCrc32 = document.querySelector("#hashCrc32");
const hashMd5 = document.querySelector("#hashMd5");
const hashSha1 = document.querySelector("#hashSha1");
const hashSha256 = document.querySelector("#hashSha256");
const importDatButton = document.querySelector("#importDatButton");
const importState = document.querySelector("#importState");
const loginButton = document.querySelector("#loginButton");
const loginForm = document.querySelector("#loginForm");
const loginPassword = document.querySelector("#loginPassword");
const loginUsername = document.querySelector("#loginUsername");
const logoutButton = document.querySelector("#logoutButton");
const matchFilter = document.querySelector("#matchFilter");
const matchesNextButton = document.querySelector("#matchesNextButton");
const matchesPageInfo = document.querySelector("#matchesPageInfo");
const matchesPageNumberList = document.querySelector("#matchesPageNumberList");
const matchesPanel = document.querySelector("#matchesPanel");
const matchesPreviousButton = document.querySelector("#matchesPreviousButton");
const matchesSummary = document.querySelector("#matchesSummary");
const matchesTable = document.querySelector("#matchesTable");
const matchSourceFilters = document.querySelector("#matchSourceFilters");
const matchUfidSourceFilters = document.querySelector("#matchUfidSourceFilters");
const refreshAlertsButton = document.querySelector("#refreshAlertsButton");
const refreshMatchesButton = document.querySelector("#refreshMatchesButton");
const searchMatchesButton = document.querySelector("#searchMatchesButton");
const sessionPanel = document.querySelector("#sessionPanel");
const sessionUser = document.querySelector("#sessionUser");
const tabButtons = [...document.querySelectorAll("[data-tab]")];

checkApi();

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await login();
});

logoutButton.addEventListener("click", async () => {
  await logout();
});

tabButtons.forEach((button) => {
  button.addEventListener("click", async () => {
    await selectTab(button.dataset.tab || "alerts");
  });
});

alertForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await addAlert();
});

importDatButton.addEventListener("click", async () => {
  await importDat();
});

refreshAlertsButton.addEventListener("click", async () => {
  await loadAlerts();
});

clearAlertsButton.addEventListener("click", async () => {
  await clearAlerts();
});

refreshMatchesButton.addEventListener("click", async () => {
  await loadMatches();
});

searchMatchesButton.addEventListener("click", async () => {
  await searchMatches();
});

alertFilter.addEventListener("input", () => {
  state.alertsFilter = alertFilter.value.trim();
  state.alertsPage = 1;
  window.clearTimeout(alertsFilterTimer);
  alertsFilterTimer = window.setTimeout(() => {
    void loadAlerts();
  }, 250);
});

matchFilter.addEventListener("input", () => {
  state.matchesFilter = matchFilter.value.trim();
  state.matchesPage = 1;
  window.clearTimeout(matchesFilterTimer);
  matchesFilterTimer = window.setTimeout(() => {
    void loadMatches();
  }, 250);
});

alertsPreviousButton.addEventListener("click", async () => {
  await goToAlertsPage(state.alertsPage - 1);
});

alertsNextButton.addEventListener("click", async () => {
  await goToAlertsPage(state.alertsPage + 1);
});

matchesPreviousButton.addEventListener("click", async () => {
  await goToMatchesPage(state.matchesPage - 1);
});

matchesNextButton.addEventListener("click", async () => {
  await goToMatchesPage(state.matchesPage + 1);
});

alertsPageNumberList.addEventListener("click", async (event) => {
  const button = event.target?.closest?.("[data-page]");
  if (!button) {
    return;
  }
  await goToAlertsPage(Number(button.dataset.page || "1"));
});

matchesPageNumberList.addEventListener("click", async (event) => {
  const button = event.target?.closest?.("[data-page]");
  if (!button) {
    return;
  }
  await goToMatchesPage(Number(button.dataset.page || "1"));
});

if (matchSourceFilters) {
  matchSourceFilters.addEventListener("click", async (event) => {
    const button = event.target?.closest?.("[data-source-key]");
    if (!button || state.loadingMatches || state.loadingSources || state.clearingAlerts) {
      return;
    }
    const key = button.dataset.sourceKey || "";
    if (!key) {
      if (!state.selectedSourceKeys.length) {
        return;
      }
      state.selectedSourceKeys = [];
    } else {
      const selected = new Set(state.selectedSourceKeys);
      if (selected.has(key)) {
        selected.delete(key);
      } else {
        selected.add(key);
      }
      state.selectedSourceKeys = [...selected];
    }
    state.matchesPage = 1;
    renderSourceFilters();
    await loadMatches();
  });
}

if (matchUfidSourceFilters) {
  matchUfidSourceFilters.addEventListener("click", async (event) => {
    const button = event.target?.closest?.("[data-ufid-source]");
    if (!button || state.loadingMatches || state.loadingUfidSources || state.clearingAlerts) {
      return;
    }
    const source = button.dataset.ufidSource || "";
    if (!source) {
      if (!state.selectedUfidSources.length) {
        return;
      }
      state.selectedUfidSources = [];
    } else {
      const selected = new Set(state.selectedUfidSources);
      if (selected.has(source)) {
        selected.delete(source);
      } else {
        selected.add(source);
      }
      state.selectedUfidSources = [...selected];
    }
    state.matchesPage = 1;
    renderUfidSourceFilters();
    await loadMatches();
  });
}

async function checkApi() {
  try {
    await fetchJson("/health", undefined, "API unavailable");
  } catch {
    apiStatus.textContent = "API offline";
    apiStatus.className = "status error";
    setGoldrushState("API offline", "error");
    return;
  }

  apiStatus.textContent = "API online";
  apiStatus.className = "status ok";
  await loadSession();
  if (state.user) {
    await loadMatchFilterOptions();
    await loadAlerts();
  } else {
    renderSourceFilters();
    renderUfidSourceFilters();
    renderAlertsMessage("Log in to manage Goldrush alerts.");
    renderMatchesMessage("Log in to view Goldrush matches.");
    setGoldrushState("Login required", "warn");
  }
}

async function login() {
  const username = loginUsername.value.trim();
  const password = loginPassword.value;
  if (!username || !password) {
    setGoldrushState("Enter username and password", "warn");
    return;
  }

  loginButton.disabled = true;
  try {
    const body = await fetchJson("/api/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    }, "Login failed");
    state.user = body.user;
    loginPassword.value = "";
    state.alertsPage = 1;
    state.matchesPage = 1;
    renderSession();
    setGoldrushState(`Logged in as ${state.user.username}`, "ok");
    await loadMatchFilterOptions();
    await loadAlerts();
    if (state.activeTab === "matches") {
      await loadMatches();
    }
  } catch (error) {
    setGoldrushState(error.message, "error");
  } finally {
    loginButton.disabled = false;
  }
}

async function logout() {
  try {
    await fetchJson("/api/v1/auth/logout", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    }, "Logout failed");
  } catch {
    // The local UI can still be cleared if the server session has expired.
  }
  state.user = null;
  state.alerts = [];
  state.matches = [];
  state.alertsPage = 1;
  state.matchesPage = 1;
  state.alertsTotal = 0;
  state.matchesTotal = 0;
  state.sourceOptions = [];
  state.selectedSourceKeys = [];
  state.ufidSourceOptions = [];
  state.selectedUfidSources = [DEFAULT_UFID_SOURCE_VALUE];
  renderSession();
  renderSourceFilters();
  renderUfidSourceFilters();
  renderAlertsMessage("Log in to manage Goldrush alerts.");
  renderMatchesMessage("Log in to view Goldrush matches.");
  setGoldrushState("Logged out", "quiet");
}

async function loadSession() {
  try {
    const body = await fetchJson("/api/v1/auth/session", undefined, "Session check failed");
    state.user = body.authenticated ? body.user : null;
  } catch {
    state.user = null;
  }
  renderSession();
}

async function selectTab(tabName) {
  state.activeTab = tabName === "matches" ? "matches" : "alerts";
  tabButtons.forEach((button) => {
    const active = button.dataset.tab === state.activeTab;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
  });
  alertsPanel.hidden = state.activeTab !== "alerts";
  matchesPanel.hidden = state.activeTab !== "matches";
  if (state.activeTab === "matches" && state.user && !state.matches.length) {
    await loadMatches();
  }
}

async function addAlert() {
  if (!state.user || !canContribute()) {
    setGoldrushState("Contributor role required", "warn");
    return;
  }
  const hashes = readHashInputs();
  if (!Object.keys(hashes).length) {
    setGoldrushState("Enter at least one supported hash", "warn");
    return;
  }

  addAlertButton.disabled = true;
  try {
    const body = await fetchJson("/api/v1/goldrush/alerts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: alertName.value.trim(),
        description: alertDescription.value.trim(),
        size_bytes: alertSize.value.trim() || null,
        hashes,
      }),
    }, "Add alert failed");
    clearHashInputs();
    if (body.created) {
      setGoldrushState("Alert added", "ok");
    } else {
      setGoldrushState("Alert already existed", "quiet");
    }
    await loadAlerts();
    await loadMatchFilterOptions();
    state.matchesPage = 1;
    if (state.activeTab === "matches") {
      await loadMatches();
    }
  } catch (error) {
    setGoldrushState(error.message, "error");
  } finally {
    addAlertButton.disabled = false;
    renderSession();
  }
}

async function importDat() {
  if (!state.user || !canContribute()) {
    setImportState("Contributor role required", "warn");
    return;
  }
  const file = datFileInput.files?.[0];
  if (!file) {
    setImportState("Choose a DAT file", "warn");
    return;
  }

  importDatButton.disabled = true;
  setImportState("Reading DAT", "quiet");
  try {
    const text = await file.text();
    setImportState("Importing DAT", "quiet");
    const body = await fetchJson("/api/v1/goldrush/import-dat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename: file.name, text }),
    }, "DAT import failed");
    const errorText = body.errors?.length ? `, ${body.errors.length} row errors` : "";
    setImportState(
      `${body.created} created, ${body.skipped} skipped from ${body.parsed} rows${errorText}`,
      body.errors?.length ? "warn" : "ok",
    );
    state.alertsPage = 1;
    state.matchesPage = 1;
    await loadAlerts();
    await loadMatchFilterOptions();
    if (state.activeTab === "matches") {
      await loadMatches();
    }
  } catch (error) {
    setImportState(error.message, "error");
  } finally {
    importDatButton.disabled = false;
    renderSession();
  }
}

async function clearAlerts() {
  if (!state.user || !canContribute()) {
    setGoldrushState("Contributor role required", "warn");
    return;
  }
  if (state.clearingAlerts) {
    return;
  }

  const confirmed = window.confirm("Erase your Goldrush alerts? This cannot be undone.");
  if (!confirmed) {
    return;
  }

  state.clearingAlerts = true;
  state.alertsRequestId += 1;
  state.matchesRequestId += 1;
  stopMatchesLoadingFeedback();
  state.loadingAlerts = false;
  state.loadingMatches = false;
  state.loadingSources = false;
  state.loadingUfidSources = false;
  setGoldrushState("Erasing alerts", "quiet");
  renderSession();
  try {
    const body = await fetchJson("/api/v1/goldrush/alerts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "clear" }),
    }, "Erase alerts failed");
    state.alerts = [];
    state.matches = [];
    state.alertsPage = 1;
    state.matchesPage = 1;
    state.alertsTotal = 0;
    state.matchesTotal = 0;
    state.sourceOptions = [];
    state.selectedSourceKeys = [];
    state.ufidSourceOptions = [];
    state.selectedUfidSources = [DEFAULT_UFID_SOURCE_VALUE];
    renderSourceFilters();
    renderUfidSourceFilters();
    renderAlertsMessage("No alerts.");
    renderMatchesMessage("No UFID hits.");
    setGoldrushState(`${body.deleted || 0} alerts erased`, "ok");
  } catch (error) {
    setGoldrushState(error.message, "error");
  } finally {
    state.clearingAlerts = false;
    renderSession();
  }
}

async function loadMatchFilterOptions() {
  await Promise.all([loadAlertSources(), loadUfidSources()]);
}

async function loadAlertSources() {
  if (!state.user) {
    state.sourceOptions = [];
    state.selectedSourceKeys = [];
    renderSourceFilters();
    return;
  }

  state.loadingSources = true;
  renderSourceFilters();
  try {
    const body = await fetchJson("/api/v1/goldrush/alert-sources", undefined, "Load alert sources failed");
    state.sourceOptions = body.sources || [];
    const validKeys = new Set(state.sourceOptions.map((source) => source.source_key).filter(Boolean));
    state.selectedSourceKeys = state.selectedSourceKeys.filter((key) => validKeys.has(key));
    renderSourceFilters();
  } catch (error) {
    setGoldrushState(error.message, "error");
  } finally {
    state.loadingSources = false;
    renderSourceFilters();
    renderSession();
  }
}

async function loadUfidSources() {
  if (!state.user) {
    state.ufidSourceOptions = [];
    state.selectedUfidSources = [DEFAULT_UFID_SOURCE_VALUE];
    renderUfidSourceFilters();
    return;
  }

  state.loadingUfidSources = true;
  renderUfidSourceFilters();
  try {
    const body = await fetchJson("/api/v1/goldrush/ufid-sources", undefined, "Load UFID sources failed");
    state.ufidSourceOptions = body.sources || [];
    const validValues = new Set(state.ufidSourceOptions.map((source) => source.source_value).filter(Boolean));
    state.selectedUfidSources = state.selectedUfidSources.filter(
      (source) => validValues.has(source) || source === DEFAULT_UFID_SOURCE_VALUE,
    );
    renderUfidSourceFilters();
  } catch (error) {
    setGoldrushState(error.message, "error");
  } finally {
    state.loadingUfidSources = false;
    renderUfidSourceFilters();
    renderSession();
  }
}

async function loadAlerts() {
  if (!state.user) {
    renderAlertsMessage("Log in to manage Goldrush alerts.");
    setGoldrushState("Login required", "warn");
    return;
  }

  const requestId = state.alertsRequestId + 1;
  state.alertsRequestId = requestId;
  state.loadingAlerts = true;
  renderSession();
  renderAlertsMessage("Loading alerts.");

  const params = new URLSearchParams({
    limit: String(PAGE_LIMIT),
    offset: String((state.alertsPage - 1) * PAGE_LIMIT),
  });
  if (state.alertsFilter) {
    params.set("q", state.alertsFilter);
  }

  try {
    const body = await fetchJson(`/api/v1/goldrush/alerts?${params.toString()}`, undefined, "Load alerts failed");
    if (requestId !== state.alertsRequestId) {
      return;
    }
    state.alerts = body.alerts || [];
    state.alertsTotal = Number.isFinite(body.total_count) ? body.total_count : state.alerts.length;
    if (state.alertsTotal > 0 && !state.alerts.length && state.alertsPage > totalAlertPages()) {
      state.alertsPage = totalAlertPages();
      await loadAlerts();
      return;
    }
    renderAlerts();
  } catch (error) {
    if (requestId !== state.alertsRequestId) {
      return;
    }
    renderAlertsMessage(error.message);
    setGoldrushState(error.message, "error");
  } finally {
    if (requestId === state.alertsRequestId) {
      state.loadingAlerts = false;
      renderSession();
    }
  }
}

async function loadMatches() {
  if (!state.user) {
    renderMatchesMessage("Log in to view Goldrush matches.");
    setGoldrushState("Login required", "warn");
    return;
  }

  const requestId = state.matchesRequestId + 1;
  state.matchesRequestId = requestId;
  state.loadingMatches = true;
  renderSession();
  renderMatchesMessage("Loading stored matches.");

  const params = new URLSearchParams({
    limit: String(PAGE_LIMIT),
    offset: String((state.matchesPage - 1) * PAGE_LIMIT),
  });
  if (state.matchesFilter) {
    params.set("q", state.matchesFilter);
  }
  state.selectedSourceKeys.forEach((key) => {
    params.append("source_key", key);
  });
  state.selectedUfidSources.forEach((source) => {
    params.append("ufid_source", source);
  });

  try {
    const body = await fetchJson(`/api/v1/goldrush/matches?${params.toString()}`, undefined, "Load matches failed");
    if (requestId !== state.matchesRequestId) {
      return;
    }
    state.matches = body.matches || [];
    state.matchesTotal = Number.isFinite(body.total_count) ? body.total_count : state.matches.length;
    if (state.matchesTotal > 0 && !state.matches.length && state.matchesPage > totalMatchPages()) {
      state.matchesPage = totalMatchPages();
      await loadMatches();
      return;
    }
    renderMatches();
  } catch (error) {
    if (requestId !== state.matchesRequestId) {
      return;
    }
    renderMatchesMessage(error.message);
    setGoldrushState(error.message, "error");
  } finally {
    if (requestId === state.matchesRequestId) {
      state.loadingMatches = false;
      renderSession();
    }
  }
}

async function searchMatches() {
  if (!state.user) {
    renderMatchesMessage("Log in to search Goldrush matches.");
    setGoldrushState("Login required", "warn");
    return;
  }

  const requestId = state.matchesRequestId + 1;
  state.matchesRequestId = requestId;
  state.loadingMatches = true;
  state.matchesLoadingStartedAt = performance.now();
  renderSession();
  startMatchesLoadingFeedback(requestId);

  try {
    const body = await fetchJson("/api/v1/goldrush/matches/search", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    }, "Search matches failed");
    if (requestId !== state.matchesRequestId) {
      return;
    }
    const created = Number(body.search?.created || 0);
    const matched = Number(body.search?.matched || 0);
    setGoldrushState(`${created} new hits stored (${matched} found)`, created ? "ok" : "quiet");
    state.matchesPage = 1;
    state.loadingMatches = false;
    stopMatchesLoadingFeedback();
    await loadMatchFilterOptions();
    await loadMatches();
  } catch (error) {
    if (requestId !== state.matchesRequestId) {
      return;
    }
    renderMatchesMessage(error.message);
    setGoldrushState(error.message, "error");
  } finally {
    if (requestId === state.matchesRequestId) {
      stopMatchesLoadingFeedback();
      state.loadingMatches = false;
      renderSession();
    }
  }
}

function renderAlerts() {
  if (!state.alertsTotal) {
    renderAlertsMessage(state.alertsFilter ? "No matching alerts." : "No alerts.");
    setGoldrushState(state.alertsFilter ? "0 matching alerts" : "0 alerts", state.alertsFilter ? "warn" : "quiet");
    return;
  }
  alertsTable.innerHTML = state.alerts.map(renderAlertRow).join("");
  const start = (state.alertsPage - 1) * PAGE_LIMIT + 1;
  const end = start + state.alerts.length - 1;
  setGoldrushState(`${start}-${end} of ${state.alertsTotal} alerts`, "ok");
  renderAlertPagination();
}

function renderAlertRow(alert) {
  return `
    <tr>
      <td>
        <strong>${escapeHtml(alert.name)}</strong>
        <span class="meta-type">#${escapeHtml(alert.id)}</span>
      </td>
      <td>${escapeHtml(alert.description)}</td>
      <td>${escapeHtml(formatBytes(alert.size_bytes))}</td>
      <td>${renderHashList(alert.hashes || {})}</td>
      <td>
        <strong>${escapeHtml(alert.source_name || alert.source_type || "Manual")}</strong>
        ${alert.source_detail ? `<span class="meta-type">${escapeHtml(alert.source_detail)}</span>` : ""}
      </td>
    </tr>
  `;
}

function renderMatches() {
  const filtering = Boolean(
    state.matchesFilter
    || state.selectedSourceKeys.length
    || state.selectedUfidSources.length
  );
  if (!state.matchesTotal) {
    renderMatchesMessage(filtering ? "No matching UFID hits." : "No UFID hits.");
    setGoldrushState(filtering ? "0 matching hits" : "0 hits", filtering ? "warn" : "quiet");
    return;
  }
  matchesTable.innerHTML = state.matches.map(renderMatchRow).join("");
  const start = (state.matchesPage - 1) * PAGE_LIMIT + 1;
  const end = start + state.matches.length - 1;
  const sourceSummary = selectedFilterSummary();
  const suffix = sourceSummary ? ` from ${sourceSummary}` : "";
  setGoldrushState(`${start}-${end} of ${state.matchesTotal} hits${suffix}`, "ok");
  renderMatchPagination();
}

function renderMatchRow(match) {
  const alert = match.alert || {};
  const file = match.file || {};
  const matched = match.matched_algorithms || [];
  return `
    <tr>
      <td>
        <strong>${escapeHtml(alert.name || "")}</strong>
        <span class="meta-type">${escapeHtml(alert.description || "")}</span>
      </td>
      <td>
        <strong>UFID ${escapeHtml(file.id || "")}</strong>
        <span class="meta-type">${escapeHtml(file.display_name || "")}</span>
        <span class="meta-type">${escapeHtml(formatBytes(file.size_bytes))}</span>
      </td>
      <td>${renderMatchSource(file)}</td>
      <td class="ia-link-cell">${renderIaItemLink(file.internet_archive, file.id)}</td>
      <td>
        <div class="chip-list">
          ${matched.map((algorithm) => `<span class="chip">${escapeHtml(algorithm)}</span>`).join("")}
          ${match.size_matched ? '<span class="chip">size</span>' : ""}
        </div>
      </td>
    </tr>
  `;
}

function renderMatchSource(file) {
  const source = file?.source;
  if (!source) {
    return '<span class="meta-type">Unspecified</span>';
  }
  const internetArchive = file?.internet_archive;
  const detail = source.source_value === DEFAULT_UFID_SOURCE_VALUE && internetArchive
    ? [
        internetArchive.identifier,
        internetArchive.file_format || internetArchive.file_source || internetArchive.file_name,
      ].filter(Boolean).join(" / ")
    : source.description || source.external_reference || "";
  return `
    <strong>${escapeHtml(source.label || source.source_value || "")}</strong>
    ${detail ? `<span class="meta-type">${escapeHtml(detail)}</span>` : ""}
  `;
}

function renderHashList(hashes, highlights = []) {
  const rows = HASH_COLUMNS
    .filter((algorithm) => hashes[algorithm])
    .map((algorithm) => {
      const highlighted = highlights.includes(algorithm);
      return `
        <div class="hash-line${highlighted ? " highlighted" : ""}">
          <span>${escapeHtml(algorithm)}</span>
          <code>${escapeHtml(hashes[algorithm])}</code>
        </div>
      `;
    });
  return rows.length ? `<div class="hash-list">${rows.join("")}</div>` : "";
}

function renderIaItemLink(source, fileId) {
  if (!source) {
    return '<span class="meta-type">No IA item link</span>';
  }
  const href = safeHttpUrl(source.item_url);
  const identifier = source.identifier || "Internet Archive item";
  const parentDetail = source.source_file_id && source.source_file_id !== fileId
    ? `<span class="meta-type">via UFID ${escapeHtml(source.source_file_id)}</span>`
    : "";
  const fileDetail = source.file_name
    ? `<span class="meta-type">${escapeHtml(source.file_name)}</span>`
    : "";
  if (!href) {
    return `
      <span>${escapeHtml(identifier)}</span>
      ${parentDetail}
      ${fileDetail}
    `;
  }
  return `
    <a href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer">
      ${escapeHtml(identifier)}
    </a>
    ${parentDetail}
    ${fileDetail}
  `;
}

function renderAlertsMessage(message) {
  alertsTable.innerHTML = `<tr><td colspan="5">${escapeHtml(message)}</td></tr>`;
  renderAlertPagination();
}

function renderMatchesMessage(message) {
  matchesTable.innerHTML = `<tr><td colspan="5">${escapeHtml(message)}</td></tr>`;
  renderMatchPagination();
}

function renderSourceFilters() {
  if (!matchSourceFilters) {
    return;
  }
  const authenticated = Boolean(state.user);
  const disabled = !authenticated || state.loadingMatches || state.loadingSources || state.clearingAlerts;
  if (!authenticated) {
    matchSourceFilters.innerHTML = "";
    return;
  }

  const allActive = state.selectedSourceKeys.length === 0;
  const buttons = [
    renderSourceFilterButton("", "All alert lists", allActive, disabled),
    ...state.sourceOptions.map((source) => {
      const key = source.source_key || "";
      const active = state.selectedSourceKeys.includes(key);
      return renderSourceFilterButton(key, sourceOptionLabel(source), active, disabled);
    }),
  ];
  matchSourceFilters.innerHTML = buttons.join("");
}

function renderUfidSourceFilters() {
  if (!matchUfidSourceFilters) {
    return;
  }
  const authenticated = Boolean(state.user);
  const disabled = !authenticated || state.loadingMatches || state.loadingUfidSources || state.clearingAlerts;
  if (!authenticated) {
    matchUfidSourceFilters.innerHTML = "";
    return;
  }

  const options = ufidSourceOptionsWithSelected();
  const allActive = state.selectedUfidSources.length === 0;
  const buttons = [
    renderUfidSourceFilterButton("", "All UFID sources", allActive, disabled),
    ...options.map((source) => {
      const value = source.source_value || "";
      const active = state.selectedUfidSources.includes(value);
      return renderUfidSourceFilterButton(value, ufidSourceOptionLabel(source), active, disabled);
    }),
  ];
  matchUfidSourceFilters.innerHTML = buttons.join("");
}

function renderSourceFilterButton(key, label, active, disabled) {
  return `
    <button
      class="source-filter-button${active ? " active" : ""}"
      type="button"
      data-source-key="${escapeHtml(key)}"
      aria-pressed="${active ? "true" : "false"}"
      ${disabled ? "disabled" : ""}
    >${escapeHtml(label)}</button>
  `;
}

function renderUfidSourceFilterButton(source, label, active, disabled) {
  return `
    <button
      class="source-filter-button${active ? " active" : ""}"
      type="button"
      data-ufid-source="${escapeHtml(source)}"
      aria-pressed="${active ? "true" : "false"}"
      ${disabled ? "disabled" : ""}
    >${escapeHtml(label)}</button>
  `;
}

function sourceOptionLabel(source) {
  const entries = Number(source.alert_count || 0);
  const hits = Number(source.hit_count || 0);
  const label = source.label || source.source_name || source.source_type || "Manual";
  return entries > 0 ? `${label} (${hits}/${entries})` : label;
}

function ufidSourceOptionsWithSelected() {
  const byValue = new Map(
    state.ufidSourceOptions
      .filter((source) => source.source_value)
      .map((source) => [source.source_value, source]),
  );
  state.selectedUfidSources.forEach((source) => {
    if (source && !byValue.has(source)) {
      byValue.set(source, {
        source_value: source,
        label: ufidSourceLabel(source),
        hit_count: 0,
      });
    }
  });
  return [...byValue.values()].sort((left, right) => {
    if (left.source_value === DEFAULT_UFID_SOURCE_VALUE) {
      return -1;
    }
    if (right.source_value === DEFAULT_UFID_SOURCE_VALUE) {
      return 1;
    }
    return ufidSourceLabel(left.source_value).localeCompare(ufidSourceLabel(right.source_value));
  });
}

function ufidSourceOptionLabel(source) {
  const hits = Number(source.hit_count || 0);
  const label = source.label || ufidSourceLabel(source.source_value);
  return hits > 0 ? `${label} (${hits})` : label;
}

function ufidSourceLabel(source) {
  if (source === DEFAULT_UFID_SOURCE_VALUE) {
    return "Internet Archive";
  }
  return source || "Unknown";
}

function selectedSourceSummary() {
  if (!state.selectedSourceKeys.length) {
    return "";
  }
  const labels = new Map(
    state.sourceOptions.map((source) => [
      source.source_key,
      source.label || source.source_name || source.source_type || source.source_key,
    ]),
  );
  return state.selectedSourceKeys.map((key) => labels.get(key) || key).join(", ");
}

function selectedUfidSourceSummary() {
  if (!state.selectedUfidSources.length) {
    return "";
  }
  const labels = new Map(
    ufidSourceOptionsWithSelected().map((source) => [
      source.source_value,
      source.label || ufidSourceLabel(source.source_value),
    ]),
  );
  return state.selectedUfidSources.map((source) => labels.get(source) || ufidSourceLabel(source)).join(", ");
}

function selectedFilterSummary() {
  return [selectedSourceSummary(), selectedUfidSourceSummary()].filter(Boolean).join(", ");
}

function startMatchesLoadingFeedback(requestId) {
  stopMatchesLoadingFeedback();
  renderMatchesLoadingMessage();
  matchesLoadingTimer = window.setInterval(() => {
    if (requestId !== state.matchesRequestId || !state.loadingMatches) {
      stopMatchesLoadingFeedback();
      return;
    }
    renderMatchesLoadingMessage();
  }, 500);
}

function stopMatchesLoadingFeedback() {
  if (matchesLoadingTimer !== null) {
    window.clearInterval(matchesLoadingTimer);
    matchesLoadingTimer = null;
  }
  state.matchesLoadingStartedAt = 0;
}

function renderMatchesLoadingMessage() {
  const elapsedSeconds = state.matchesLoadingStartedAt
    ? (performance.now() - state.matchesLoadingStartedAt) / 1000
    : 0;
  const elapsed = elapsedSeconds >= 1 ? ` (${elapsedSeconds.toFixed(1)}s)` : "";
  renderMatchesMessage(`Searching matches${elapsed}.`);
  const sourceSummary = selectedFilterSummary();
  matchesSummary.textContent = sourceSummary
    ? `Scanning ${sourceSummary} alert hashes against known files.`
    : "Scanning alert hashes against known files.";
  setGoldrushState(`Searching matches${elapsed}`, "quiet");
}

function renderSession() {
  const authenticated = Boolean(state.user);
  const contributor = canContribute();
  const alertBusy = state.loadingAlerts || state.clearingAlerts;
  loginForm.hidden = authenticated;
  sessionPanel.hidden = !authenticated;
  alertFilter.disabled = !authenticated || alertBusy;
  matchFilter.disabled = !authenticated || state.loadingMatches || state.clearingAlerts;
  refreshAlertsButton.disabled = !authenticated || alertBusy;
  clearAlertsButton.disabled = !authenticated || !contributor || state.clearingAlerts;
  refreshMatchesButton.disabled = !authenticated || state.loadingMatches || state.clearingAlerts;
  searchMatchesButton.disabled = !authenticated || state.loadingMatches || state.clearingAlerts;
  alertForm.querySelectorAll("input, textarea, button").forEach((control) => {
    control.disabled = !authenticated || !contributor || alertBusy;
  });
  datFileInput.disabled = !authenticated || !contributor;
  importDatButton.disabled = !authenticated || !contributor || alertBusy;
  if (authenticated) {
    const roles = (state.user.roles || []).join(", ");
    sessionUser.textContent = `${state.user.username}${roles ? ` (${roles})` : ""}`;
  } else {
    sessionUser.textContent = "";
  }
  renderAlertPagination();
  renderMatchPagination();
  renderSourceFilters();
  renderUfidSourceFilters();
}

function renderAlertPagination() {
  const pages = totalAlertPages();
  const authenticated = Boolean(state.user);
  const disabled = state.loadingAlerts || state.clearingAlerts;
  alertsPageInfo.textContent = `Page ${Math.min(state.alertsPage, pages)} of ${pages}`;
  alertsSummary.textContent = paginationSummary(state.alertsPage, state.alerts.length, state.alertsTotal, "alerts");
  alertsPreviousButton.disabled = !authenticated || disabled || state.alertsPage <= 1;
  alertsNextButton.disabled = !authenticated || disabled || state.alertsPage >= pages;
  alertsPageNumberList.innerHTML = pageWindow(state.alertsPage, pages)
    .map((item) => renderPageButton(item, state.alertsPage, authenticated, disabled))
    .join("");
}

function renderMatchPagination() {
  const pages = totalMatchPages();
  const authenticated = Boolean(state.user);
  const disabled = state.loadingMatches || state.clearingAlerts;
  matchesPageInfo.textContent = `Page ${Math.min(state.matchesPage, pages)} of ${pages}`;
  matchesSummary.textContent = paginationSummary(state.matchesPage, state.matches.length, state.matchesTotal, "matches");
  matchesPreviousButton.disabled = !authenticated || disabled || state.matchesPage <= 1;
  matchesNextButton.disabled = !authenticated || disabled || state.matchesPage >= pages;
  matchesPageNumberList.innerHTML = pageWindow(state.matchesPage, pages)
    .map((item) => renderPageButton(item, state.matchesPage, authenticated, disabled))
    .join("");
}

function paginationSummary(page, shown, total, noun) {
  if (total && shown) {
    const start = (page - 1) * PAGE_LIMIT + 1;
    const end = start + shown - 1;
    return `Rows ${start}-${end} of ${total}`;
  }
  return total ? `${total} ${noun}` : `No ${noun} loaded.`;
}

function renderPageButton(item, currentPage, authenticated, loading) {
  if (item === "gap") {
    return `<span class="page-gap" aria-hidden="true">...</span>`;
  }
  const current = item === currentPage;
  return `
    <button
      class="secondary-button page-number-button${current ? " current-page" : ""}"
      type="button"
      data-page="${item}"
      ${current ? 'aria-current="page"' : ""}
      ${!authenticated || loading || current ? "disabled" : ""}
    >${item}</button>
  `;
}

async function goToAlertsPage(page) {
  if (state.loadingAlerts) {
    return;
  }
  const target = clampPage(page, totalAlertPages());
  if (target === state.alertsPage) {
    return;
  }
  state.alertsPage = target;
  await loadAlerts();
}

async function goToMatchesPage(page) {
  if (state.loadingMatches) {
    return;
  }
  const target = clampPage(page, totalMatchPages());
  if (target === state.matchesPage) {
    return;
  }
  state.matchesPage = target;
  await loadMatches();
}

function pageWindow(currentPage, pageCount) {
  if (pageCount <= 7) {
    return Array.from({ length: pageCount }, (_, index) => index + 1);
  }

  const pages = new Set([1, pageCount]);
  const start = Math.max(2, currentPage - 2);
  const end = Math.min(pageCount - 1, currentPage + 2);
  for (let page = start; page <= end; page += 1) {
    pages.add(page);
  }

  const sortedPages = [...pages].sort((a, b) => a - b);
  const items = [];
  for (const page of sortedPages) {
    const previous = items[items.length - 1];
    if (typeof previous === "number" && page - previous > 1) {
      items.push("gap");
    }
    items.push(page);
  }
  return items;
}

function totalAlertPages() {
  return Math.max(1, Math.ceil(state.alertsTotal / PAGE_LIMIT));
}

function totalMatchPages() {
  return Math.max(1, Math.ceil(state.matchesTotal / PAGE_LIMIT));
}

function clampPage(page, pageCount) {
  const parsed = Math.trunc(Number(page));
  if (!Number.isFinite(parsed)) {
    return 1;
  }
  return Math.min(Math.max(parsed, 1), pageCount);
}

function canContribute() {
  const roles = new Set(state.user?.roles || []);
  return roles.has("contributor") || roles.has("curator") || roles.has("admin");
}

function readHashInputs() {
  const pairs = [
    ["crc32", hashCrc32.value],
    ["md5", hashMd5.value],
    ["sha1", hashSha1.value],
    ["sha256", hashSha256.value],
    ["blake3", hashBlake3.value],
  ];
  return Object.fromEntries(
    pairs
      .map(([algorithm, value]) => [algorithm, value.trim().toLowerCase()])
      .filter(([, value]) => value),
  );
}

function clearHashInputs() {
  hashCrc32.value = "";
  hashMd5.value = "";
  hashSha1.value = "";
  hashSha256.value = "";
  hashBlake3.value = "";
}

function setGoldrushState(message, type = "quiet") {
  goldrushState.textContent = message;
  goldrushState.className = `status ${type}`;
}

function setImportState(message, type = "quiet") {
  importState.textContent = message;
  importState.className = `status ${type}`;
}

async function fetchJson(url, options, failureMessage) {
  let response;
  try {
    response = await fetch(url, { credentials: "same-origin", ...options });
  } catch (error) {
    throw new Error(`${failureMessage}: ${error.message}`);
  }

  const text = await response.text();
  let body = {};
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      if (!response.ok) {
        throw new Error(`${failureMessage}: ${httpErrorSummary(response, text)}`);
      }
      throw new Error(`${failureMessage}: invalid JSON response`);
    }
  }
  if (!response.ok) {
    const detail = [body.error, body.conflict_type, body.file_id ? `UFID ${body.file_id}` : null]
      .filter(Boolean)
      .join(" - ");
    throw new Error(detail || failureMessage || `HTTP ${response.status}`);
  }
  return body;
}

function httpErrorSummary(response, text) {
  const status = `HTTP ${response.status}${response.statusText ? ` ${response.statusText}` : ""}`;
  const plainText = String(text || "")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return plainText ? `${status}: ${plainText.slice(0, 180)}` : status;
}

function formatBytes(value) {
  if (value === null || value === undefined || value === "") {
    return "";
  }
  const size = Number(value);
  if (!Number.isFinite(size)) {
    return String(value);
  }
  return new Intl.NumberFormat().format(size);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function safeHttpUrl(value) {
  if (!value) {
    return "";
  }
  try {
    const url = new URL(String(value));
    return url.protocol === "http:" || url.protocol === "https:" ? url.href : "";
  } catch {
    return "";
  }
}
