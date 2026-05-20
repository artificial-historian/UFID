const PAGE_LIMIT = 200;
const HASH_COLUMNS = ["crc32", "md5", "sha1", "sha256", "blake3"];

const state = {
  user: null,
  files: [],
  loading: false,
  page: 1,
  pageSize: PAGE_LIMIT,
  totalCount: 0,
  sortKey: "id",
  sortDirection: "desc",
  filter: "",
  requestId: 0,
};

let filterTimer = null;

const apiStatus = document.querySelector("#apiStatus");
const fileFilter = document.querySelector("#fileFilter");
const filesTable = document.querySelector("#filesTable");
const listState = document.querySelector("#listState");
const loginButton = document.querySelector("#loginButton");
const loginForm = document.querySelector("#loginForm");
const loginPassword = document.querySelector("#loginPassword");
const loginUsername = document.querySelector("#loginUsername");
const logoutButton = document.querySelector("#logoutButton");
const nextPageButton = document.querySelector("#nextPageButton");
const pageInfo = document.querySelector("#pageInfo");
const pageNumberList = document.querySelector("#pageNumberList");
const pageSummary = document.querySelector("#pageSummary");
const previousPageButton = document.querySelector("#previousPageButton");
const refreshButton = document.querySelector("#refreshButton");
const sessionPanel = document.querySelector("#sessionPanel");
const sessionUser = document.querySelector("#sessionUser");
const sortButtons = [...document.querySelectorAll("[data-sort]")];

checkApi();

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await login();
});

logoutButton.addEventListener("click", async () => {
  await logout();
});

refreshButton.addEventListener("click", async () => {
  await loadKnownFiles();
});

fileFilter.addEventListener("input", () => {
  state.filter = fileFilter.value.trim();
  state.page = 1;
  window.clearTimeout(filterTimer);
  filterTimer = window.setTimeout(() => {
    void loadKnownFiles();
  }, 250);
});

previousPageButton.addEventListener("click", async () => {
  await goToPage(state.page - 1);
});

nextPageButton.addEventListener("click", async () => {
  await goToPage(state.page + 1);
});

pageNumberList.addEventListener("click", async (event) => {
  const button = event.target?.closest?.("[data-page]");
  if (!button) {
    return;
  }
  await goToPage(Number(button.dataset.page || "1"));
});

async function goToPage(page) {
  if (state.loading) {
    return;
  }
  const pages = totalPages();
  const target = Math.min(Math.max(Math.trunc(page), 1), pages);
  if (!Number.isFinite(target) || target === state.page) {
    return;
  }
  state.page = target;
  await loadKnownFiles();
}

sortButtons.forEach((button) => {
  button.addEventListener("click", async () => {
    const key = button.dataset.sort;
    if (!key || state.loading) {
      return;
    }
    if (state.sortKey === key) {
      state.sortDirection = state.sortDirection === "asc" ? "desc" : "asc";
    } else {
      state.sortKey = key;
      state.sortDirection = key === "id" ? "desc" : "asc";
    }
    state.page = 1;
    updateSortHeaders();
    await loadKnownFiles();
  });
});

async function checkApi() {
  try {
    await fetchJson("/health", undefined, "API unavailable");
    apiStatus.textContent = "API online";
    apiStatus.className = "status ok";
    await loadSession();
    if (state.user) {
      await loadKnownFiles();
    } else {
      renderFilesMessage("Log in to view known files.");
      setListState("Login required", "warn");
    }
  } catch {
    apiStatus.textContent = "API offline";
    apiStatus.className = "status error";
    setListState("API offline", "error");
  }
}

async function login() {
  const username = loginUsername.value.trim();
  const password = loginPassword.value;
  if (!username || !password) {
    setListState("Enter username and password", "warn");
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
    state.page = 1;
    renderSession();
    setListState(`Logged in as ${state.user.username}`, "ok");
    await loadKnownFiles();
  } catch (error) {
    setListState(error.message, "error");
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
    // Clear the local UI even if the server-side session was already gone.
  }
  state.user = null;
  state.files = [];
  state.page = 1;
  state.totalCount = 0;
  renderSession();
  renderFilesMessage("Log in to view known files.");
  setListState("Logged out", "quiet");
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

function renderSession() {
  const authenticated = Boolean(state.user);
  loginForm.hidden = authenticated;
  sessionPanel.hidden = !authenticated;
  refreshButton.disabled = !authenticated || state.loading;
  fileFilter.disabled = !authenticated || state.loading;
  sortButtons.forEach((button) => {
    button.disabled = !authenticated || state.loading;
  });
  if (authenticated) {
    const roles = (state.user.roles || []).join(", ");
    sessionUser.textContent = `${state.user.username}${roles ? ` (${roles})` : ""}`;
  } else {
    sessionUser.textContent = "";
  }
  renderPagination();
  updateSortHeaders();
}

async function loadKnownFiles() {
  if (!state.user) {
    renderFilesMessage("Log in to view known files.");
    setListState("Login required", "warn");
    return;
  }

  const requestId = state.requestId + 1;
  state.requestId = requestId;
  state.loading = true;
  state.files = [];
  renderSession();
  renderFilesMessage("Loading records.");
  setListState("Loading files", "quiet");

  const offset = (state.page - 1) * state.pageSize;
  const params = new URLSearchParams({
    limit: String(state.pageSize),
    offset: String(offset),
    sort: state.sortKey,
    direction: state.sortDirection,
  });
  if (state.filter) {
    params.set("q", state.filter);
  }

  try {
    const body = await fetchJson(`/api/v1/files?${params.toString()}`, undefined, "Load failed");
    if (requestId !== state.requestId) {
      return;
    }
    state.files = body.files || [];
    state.totalCount = Number.isFinite(body.total_count) ? body.total_count : state.files.length;
    if (state.totalCount > 0 && state.files.length === 0 && state.page > totalPages()) {
      state.page = totalPages();
      await loadKnownFiles();
      return;
    }
    renderFiles();
  } catch (error) {
    if (requestId !== state.requestId) {
      return;
    }
    renderFilesMessage(error.message);
    setListState(error.message, "error");
  } finally {
    if (requestId === state.requestId) {
      state.loading = false;
      renderSession();
    }
  }
}

function renderFiles() {
  const total = state.totalCount;
  const shown = state.files.length;
  if (!total) {
    renderFilesMessage(state.filter ? "No matching files." : "No known files.");
    setListState(state.filter ? "0 matching files" : "0 files", state.filter ? "warn" : "quiet");
    return;
  }
  if (!shown) {
    renderFilesMessage("No records on this page.");
    setListState(`${total} files`, "warn");
    return;
  }

  filesTable.innerHTML = state.files.map(renderFileRow).join("");
  const start = (state.page - 1) * state.pageSize + 1;
  const end = start + shown - 1;
  setListState(`${start}-${end} of ${total} files`, "ok");
}

function renderFileRow(file) {
  const hashes = file.hashes || {};
  return `
    <tr>
      <td class="file-id">${escapeHtml(file.id)}</td>
      <td class="file-name">
        <strong>${escapeHtml(file.display_name || `UFID ${file.id}`)}</strong>
        ${file.content_type ? `<span>${escapeHtml(file.content_type)}</span>` : ""}
      </td>
      <td>${escapeHtml(formatBytes(file.size_bytes))}</td>
      ${HASH_COLUMNS.map((algorithm) => `<td class="hash-cell">${escapeHtml(hashes[algorithm] || "")}</td>`).join("")}
    </tr>
  `;
}

function renderFilesMessage(message) {
  filesTable.innerHTML = `<tr><td colspan="8">${escapeHtml(message)}</td></tr>`;
  renderPagination();
}

function renderPagination() {
  const pages = totalPages();
  const authenticated = Boolean(state.user);
  const total = state.totalCount;
  const shown = state.files.length;
  const start = total && shown ? (state.page - 1) * state.pageSize + 1 : 0;
  const end = total && shown ? start + shown - 1 : 0;

  pageInfo.textContent = `Page ${Math.min(state.page, pages)} of ${pages}`;
  pageSummary.textContent = total && shown
    ? `Rows ${start}-${end} of ${total}`
    : total
      ? `${total} records`
      : "No records loaded.";
  previousPageButton.disabled = !authenticated || state.loading || state.page <= 1;
  nextPageButton.disabled = !authenticated || state.loading || state.page >= pages;
  pageNumberList.innerHTML = pageWindow(state.page, pages)
    .map((item) => renderPageWindowItem(item, authenticated))
    .join("");
}

function renderPageWindowItem(item, authenticated) {
  if (item === "gap") {
    return `<span class="page-gap" aria-hidden="true">...</span>`;
  }
  const current = item === state.page;
  return `
    <button
      class="secondary-button page-number-button${current ? " current-page" : ""}"
      type="button"
      data-page="${item}"
      ${current ? 'aria-current="page"' : ""}
      ${!authenticated || state.loading || current ? "disabled" : ""}
    >${item}</button>
  `;
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

function updateSortHeaders() {
  sortButtons.forEach((button) => {
    const key = button.dataset.sort;
    const sorted = key === state.sortKey;
    const th = button.closest("th");
    const indicator = button.querySelector(".sort-indicator");
    button.setAttribute(
      "aria-label",
      sorted
        ? `Sort by ${button.textContent.trim()} ${state.sortDirection === "asc" ? "descending" : "ascending"}`
        : `Sort by ${button.textContent.trim()} ascending`,
    );
    if (th) {
      th.setAttribute(
        "aria-sort",
        sorted ? (state.sortDirection === "asc" ? "ascending" : "descending") : "none",
      );
    }
    if (indicator) {
      indicator.textContent = sorted ? (state.sortDirection === "asc" ? " ^" : " v") : "";
    }
  });
}

function totalPages() {
  return Math.max(1, Math.ceil(state.totalCount / state.pageSize));
}

function setListState(message, type) {
  listState.textContent = message;
  listState.className = `status ${type}`;
}

async function fetchJson(url, options, fallbackMessage) {
  let response;
  try {
    response = await fetch(url, { credentials: "same-origin", ...options });
  } catch (error) {
    throw new Error(`${fallbackMessage}: ${error.message}`);
  }

  const text = await response.text();
  let body = {};
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      if (!response.ok) {
        throw new Error(`${fallbackMessage}: ${text}`);
      }
      throw new Error(`${fallbackMessage}: invalid JSON response`);
    }
  }

  if (!response.ok) {
    const detail = [body.error, body.conflict_type, body.file_id ? `UFID ${body.file_id}` : null]
      .filter(Boolean)
      .join(" - ");
    throw new Error(detail || fallbackMessage);
  }
  return body;
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) {
    return "";
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[index]}`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
