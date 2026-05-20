const PAGE_LIMIT = 200;
const HASH_COLUMNS = ["crc32", "md5", "sha1", "sha256", "blake3"];

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
};

let alertsFilterTimer = null;
let matchesFilterTimer = null;

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
const refreshAlertsButton = document.querySelector("#refreshAlertsButton");
const refreshMatchesButton = document.querySelector("#refreshMatchesButton");
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

refreshMatchesButton.addEventListener("click", async () => {
  await loadMatches();
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

async function checkApi() {
  try {
    await fetchJson("/health", undefined, "API unavailable");
    apiStatus.textContent = "API online";
    apiStatus.className = "status ok";
    await loadSession();
    if (state.user) {
      await loadAlerts();
    } else {
      renderAlertsMessage("Log in to manage Goldrush alerts.");
      renderMatchesMessage("Log in to view Goldrush matches.");
      setGoldrushState("Login required", "warn");
    }
  } catch {
    apiStatus.textContent = "API offline";
    apiStatus.className = "status error";
    setGoldrushState("API offline", "error");
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
  renderSession();
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
  renderMatchesMessage("Loading matches.");

  const params = new URLSearchParams({
    limit: String(PAGE_LIMIT),
    offset: String((state.matchesPage - 1) * PAGE_LIMIT),
  });
  if (state.matchesFilter) {
    params.set("q", state.matchesFilter);
  }

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
  if (!state.matchesTotal) {
    renderMatchesMessage(state.matchesFilter ? "No matching UFID hits." : "No UFID hits.");
    setGoldrushState(state.matchesFilter ? "0 matching hits" : "0 hits", state.matchesFilter ? "warn" : "quiet");
    return;
  }
  matchesTable.innerHTML = state.matches.map(renderMatchRow).join("");
  const start = (state.matchesPage - 1) * PAGE_LIMIT + 1;
  const end = start + state.matches.length - 1;
  setGoldrushState(`${start}-${end} of ${state.matchesTotal} hits`, "ok");
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
      <td>
        <div class="chip-list">
          ${matched.map((algorithm) => `<span class="chip">${escapeHtml(algorithm)}</span>`).join("")}
          ${match.size_matched ? '<span class="chip">size</span>' : ""}
        </div>
      </td>
      <td>${renderHashList(alert.hashes || {}, matched)}</td>
      <td>${renderHashList(file.hashes || {}, matched)}</td>
    </tr>
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

function renderAlertsMessage(message) {
  alertsTable.innerHTML = `<tr><td colspan="5">${escapeHtml(message)}</td></tr>`;
  renderAlertPagination();
}

function renderMatchesMessage(message) {
  matchesTable.innerHTML = `<tr><td colspan="5">${escapeHtml(message)}</td></tr>`;
  renderMatchPagination();
}

function renderSession() {
  const authenticated = Boolean(state.user);
  const contributor = canContribute();
  loginForm.hidden = authenticated;
  sessionPanel.hidden = !authenticated;
  alertFilter.disabled = !authenticated || state.loadingAlerts;
  matchFilter.disabled = !authenticated || state.loadingMatches;
  refreshAlertsButton.disabled = !authenticated || state.loadingAlerts;
  refreshMatchesButton.disabled = !authenticated || state.loadingMatches;
  alertForm.querySelectorAll("input, textarea, button").forEach((control) => {
    control.disabled = !authenticated || !contributor || state.loadingAlerts;
  });
  datFileInput.disabled = !authenticated || !contributor;
  importDatButton.disabled = !authenticated || !contributor || state.loadingAlerts;
  if (authenticated) {
    const roles = (state.user.roles || []).join(", ");
    sessionUser.textContent = `${state.user.username}${roles ? ` (${roles})` : ""}`;
  } else {
    sessionUser.textContent = "";
  }
  renderAlertPagination();
  renderMatchPagination();
}

function renderAlertPagination() {
  const pages = totalAlertPages();
  const authenticated = Boolean(state.user);
  alertsPageInfo.textContent = `Page ${Math.min(state.alertsPage, pages)} of ${pages}`;
  alertsSummary.textContent = paginationSummary(state.alertsPage, state.alerts.length, state.alertsTotal, "alerts");
  alertsPreviousButton.disabled = !authenticated || state.loadingAlerts || state.alertsPage <= 1;
  alertsNextButton.disabled = !authenticated || state.loadingAlerts || state.alertsPage >= pages;
  alertsPageNumberList.innerHTML = pageWindow(state.alertsPage, pages)
    .map((item) => renderPageButton(item, state.alertsPage, authenticated, state.loadingAlerts))
    .join("");
}

function renderMatchPagination() {
  const pages = totalMatchPages();
  const authenticated = Boolean(state.user);
  matchesPageInfo.textContent = `Page ${Math.min(state.matchesPage, pages)} of ${pages}`;
  matchesSummary.textContent = paginationSummary(state.matchesPage, state.matches.length, state.matchesTotal, "matches");
  matchesPreviousButton.disabled = !authenticated || state.loadingMatches || state.matchesPage <= 1;
  matchesNextButton.disabled = !authenticated || state.loadingMatches || state.matchesPage >= pages;
  matchesPageNumberList.innerHTML = pageWindow(state.matchesPage, pages)
    .map((item) => renderPageButton(item, state.matchesPage, authenticated, state.loadingMatches))
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
        throw new Error(`${failureMessage}: ${text}`);
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
