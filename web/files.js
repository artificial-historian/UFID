const PAGE_LIMIT = 200;
const HASH_COLUMNS = ["crc32", "md5", "sha1", "sha256", "blake3"];

const state = {
  user: null,
  files: [],
  filteredFiles: [],
  loading: false,
};

const apiStatus = document.querySelector("#apiStatus");
const fileFilter = document.querySelector("#fileFilter");
const filesTable = document.querySelector("#filesTable");
const listState = document.querySelector("#listState");
const loginButton = document.querySelector("#loginButton");
const loginForm = document.querySelector("#loginForm");
const loginPassword = document.querySelector("#loginPassword");
const loginUsername = document.querySelector("#loginUsername");
const logoutButton = document.querySelector("#logoutButton");
const refreshButton = document.querySelector("#refreshButton");
const sessionPanel = document.querySelector("#sessionPanel");
const sessionUser = document.querySelector("#sessionUser");

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
  applyFilter();
  renderFiles();
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
  state.filteredFiles = [];
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
  if (authenticated) {
    const roles = (state.user.roles || []).join(", ");
    sessionUser.textContent = `${state.user.username}${roles ? ` (${roles})` : ""}`;
  } else {
    sessionUser.textContent = "";
  }
}

async function loadKnownFiles() {
  if (!state.user) {
    renderFilesMessage("Log in to view known files.");
    setListState("Login required", "warn");
    return;
  }

  state.loading = true;
  state.files = [];
  state.filteredFiles = [];
  renderSession();
  renderFilesMessage("Loading records.");
  setListState("Loading 0 files", "quiet");

  let offset = 0;
  try {
    while (offset !== null) {
      const params = new URLSearchParams({
        limit: String(PAGE_LIMIT),
        offset: String(offset),
      });
      const body = await fetchJson(`/api/v1/files?${params.toString()}`, undefined, "Load failed");
      const files = body.files || [];
      state.files.push(...files);
      setListState(`Loading ${state.files.length} files`, "quiet");
      if (files.length === 0 || body.next_offset === null) {
        offset = null;
      } else {
        offset = body.next_offset;
      }
    }
    applyFilter();
    renderFiles();
  } catch (error) {
    renderFilesMessage(error.message);
    setListState(error.message, "error");
  } finally {
    state.loading = false;
    renderSession();
  }
}

function applyFilter() {
  const query = fileFilter.value.trim().toLowerCase();
  if (!query) {
    state.filteredFiles = [...state.files];
    return;
  }
  state.filteredFiles = state.files.filter((file) => fileSearchText(file).includes(query));
}

function renderFiles() {
  const total = state.files.length;
  const shown = state.filteredFiles.length;
  if (!total) {
    renderFilesMessage("No known files.");
    setListState("0 files", "quiet");
    return;
  }
  if (!shown) {
    renderFilesMessage("No matching files.");
    setListState(`0 of ${total} files`, "warn");
    return;
  }

  filesTable.innerHTML = state.filteredFiles.map(renderFileRow).join("");
  if (shown === total) {
    setListState(`${total} files`, "ok");
  } else {
    setListState(`${shown} of ${total} files`, "ok");
  }
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
}

function fileSearchText(file) {
  const hashes = file.hashes || {};
  return [
    file.id,
    file.display_name,
    file.content_type,
    file.description,
    file.size_bytes,
    ...HASH_COLUMNS.map((algorithm) => hashes[algorithm]),
  ]
    .filter((value) => value !== null && value !== undefined)
    .join(" ")
    .toLowerCase();
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
