const state = {
  file: null,
  hashes: {},
  sizeBytes: null,
  metadataRows: [],
  user: null,
};

const browserAlgorithms = [
  ["sha1", "SHA-1"],
  ["sha256", "SHA-256"],
];

const apiStatus = document.querySelector("#apiStatus");
const addButton = document.querySelector("#addButton");
const browseButton = document.querySelector("#browseButton");
const browseQuery = document.querySelector("#browseQuery");
const browseResults = document.querySelector("#browseResults");
const contentTypeInput = document.querySelector("#contentTypeInput");
const descriptionInput = document.querySelector("#descriptionInput");
const dropZone = document.querySelector("#dropZone");
const fileInput = document.querySelector("#fileInput");
const hashTable = document.querySelector("#hashTable");
const manualAlgorithm = document.querySelector("#manualAlgorithm");
const manualHash = document.querySelector("#manualHash");
const manualLookup = document.querySelector("#manualLookup");
const loginButton = document.querySelector("#loginButton");
const loginForm = document.querySelector("#loginForm");
const loginPassword = document.querySelector("#loginPassword");
const loginUsername = document.querySelector("#loginUsername");
const logoutButton = document.querySelector("#logoutButton");
const addMetadataButton = document.querySelector("#addMetadataButton");
const metadataDraftList = document.querySelector("#metadataDraftList");
const metadataNameInput = document.querySelector("#metadataNameInput");
const metadataNotesInput = document.querySelector("#metadataNotesInput");
const metadataTypeInput = document.querySelector("#metadataTypeInput");
const metadataValueInput = document.querySelector("#metadataValueInput");
const recordDetails = document.querySelector("#recordDetails");
const recordState = document.querySelector("#recordState");
const resetButton = document.querySelector("#resetButton");
const searchButton = document.querySelector("#searchButton");
const selectedFile = document.querySelector("#selectedFile");
const sessionPanel = document.querySelector("#sessionPanel");
const sessionUser = document.querySelector("#sessionUser");

checkApi();

dropZone.addEventListener("dragover", (event) => {
  event.preventDefault();
  dropZone.classList.add("dragging");
});

dropZone.addEventListener("dragleave", () => {
  dropZone.classList.remove("dragging");
});

dropZone.addEventListener("drop", async (event) => {
  event.preventDefault();
  dropZone.classList.remove("dragging");
  const file = event.dataTransfer.files[0];
  if (file) {
    await setFile(file);
  }
});

fileInput.addEventListener("change", async () => {
  const file = fileInput.files[0];
  if (file) {
    await setFile(file);
  }
});

searchButton.addEventListener("click", async () => {
  if (!state.user) {
    setRecordState("Log in to search UFID", "warn");
    return;
  }
  if (!state.hashes.sha1) {
    setRecordState("SHA-1 is required for browser lookup", "warn");
    return;
  }
  await lookupHash("sha1", state.hashes.sha1, state.sizeBytes);
});

addButton.addEventListener("click", async () => {
  if (!state.user) {
    setRecordState("Log in to add or enrich records", "warn");
    return;
  }
  if (!state.file || !Object.keys(state.hashes).length) {
    return;
  }
  let metadata;
  try {
    metadata = collectMetadataPayload();
  } catch {
    return;
  }

  const payload = {
    display_name: state.file.name,
    size_bytes: state.sizeBytes,
    description: descriptionInput.value.trim() || null,
    content_type: contentTypeInput.value.trim() || state.file.type || null,
    hashes: state.hashes,
    metadata,
  };

  setRecordState("Saving", "quiet");
  try {
    const body = await fetchJson("/api/v1/files", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }, "Save failed");
    setRecordState(
      body.created ? `Created UFID ${body.id}` : `Updated UFID ${body.id}`,
      "ok",
    );
    await lookupHash("sha1", state.hashes.sha1, state.sizeBytes);
  } catch (error) {
    setRecordState(error.message, "error");
  }
});

manualLookup.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.user) {
    setRecordState("Log in to search UFID", "warn");
    return;
  }
  const algorithm = manualAlgorithm.value;
  const hashValue = manualHash.value.trim();
  if (!hashValue) {
    setRecordState("Enter a hash value", "warn");
    return;
  }
  await lookupHash(algorithm, hashValue);
});

browseButton.addEventListener("click", async () => {
  if (!state.user) {
    setRecordState("Log in to browse UFID", "warn");
    return;
  }
  await browseFiles();
});

browseQuery.addEventListener("keydown", async (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    if (!state.user) {
      setRecordState("Log in to browse UFID", "warn");
      return;
    }
    await browseFiles();
  }
});

browseResults.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-file-id]");
  if (!button) {
    return;
  }
  await loadFile(button.dataset.fileId);
});

recordDetails.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-file-id]");
  if (!button) {
    return;
  }
  await loadFile(button.dataset.fileId);
});

addMetadataButton.addEventListener("click", () => {
  let row;
  try {
    row = readMetadataDraft({ requireRow: true });
  } catch {
    return;
  }
  if (metadataRowExists(row)) {
    setRecordState("That metadata row is already staged", "warn");
    return;
  }
  state.metadataRows.push(row);
  clearMetadataDraft();
  renderMetadataDraftList();
  setRecordState("Metadata staged", "ok");
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await login();
});

logoutButton.addEventListener("click", async () => {
  await logout();
});

metadataDraftList.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-metadata-index]");
  if (!button) {
    return;
  }
  state.metadataRows.splice(Number(button.dataset.metadataIndex), 1);
  renderMetadataDraftList();
});

resetButton.addEventListener("click", () => {
  state.file = null;
  state.hashes = {};
  state.sizeBytes = null;
  state.metadataRows = [];
  fileInput.value = "";
  selectedFile.textContent = "No file selected";
  contentTypeInput.value = "";
  descriptionInput.value = "";
  clearMetadataDraft();
  renderMetadataDraftList();
  updateActionState();
  renderHashes();
  renderRecord(null);
  setRecordState("Idle", "quiet");
});

async function setFile(file) {
  state.file = file;
  state.hashes = {};
  state.sizeBytes = file.size;
  selectedFile.textContent = `${file.name} - ${formatBytes(file.size)}`;
  contentTypeInput.value = file.type || "";
  searchButton.disabled = true;
  addButton.disabled = true;
  renderHashes("Hashing");

  try {
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    const computed = {
      crc32: crc32Hex(bytes),
      md5: md5Hex(bytes),
    };
    for (const [name, webCryptoName] of browserAlgorithms) {
      computed[name] = await digestHex(webCryptoName, buffer);
    }
    state.hashes = computed;
    renderHashes();
    updateActionState();
    manualAlgorithm.value = "sha1";
    manualHash.value = computed.sha1;
    setRecordState("Hashes ready", "ok");
  } catch (error) {
    renderHashes();
    setRecordState(error.message, "error");
  }
}

async function digestHex(algorithm, buffer) {
  const digest = await crypto.subtle.digest(algorithm, buffer);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function renderHashes(message = null) {
  if (message) {
    hashTable.innerHTML = `<tr><td colspan="2">${escapeHtml(message)}</td></tr>`;
    return;
  }

  const entries = Object.entries(state.hashes);
  if (!entries.length) {
    hashTable.innerHTML =
      '<tr><td colspan="2">Select a file to compute browser-supported hashes.</td></tr>';
    return;
  }

  hashTable.innerHTML = entries
    .map(
      ([algorithm, value]) => `
        <tr>
          <td>${escapeHtml(algorithm)}</td>
          <td>${escapeHtml(value)}</td>
        </tr>
      `,
    )
    .join("");
}

async function lookupHash(algorithm, hashValue, sizeBytes = null) {
  setRecordState("Searching", "quiet");
  try {
    const params = new URLSearchParams({
      algorithm,
      value: hashValue,
    });
    if (Number.isInteger(sizeBytes) && sizeBytes >= 0) {
      params.set("size", String(sizeBytes));
    }
    const body = await fetchJson(
      `/api/v1/files/by-hash?${params.toString()}`,
      undefined,
      "Lookup failed",
    );
    if (!body.found) {
      renderRecord(null);
      setRecordState("Not found", "warn");
      return;
    }
    renderRecord(body.file);
    setRecordState(`Found UFID ${body.file.id}`, "ok");
  } catch (error) {
    setRecordState(error.message, "error");
  }
}

async function loadFile(fileId) {
  setRecordState("Loading", "quiet");
  try {
    const body = await fetchJson(
      `/api/v1/files/${encodeURIComponent(fileId)}`,
      undefined,
      "Load failed",
    );
    renderRecord(body.file);
    setRecordState(`Loaded UFID ${body.file.id}`, "ok");
  } catch (error) {
    setRecordState(error.message, "error");
  }
}

async function browseFiles() {
  if (!state.user) {
    browseResults.innerHTML = "<p>Log in to browse records.</p>";
    return;
  }
  browseResults.innerHTML = "<p>Loading records.</p>";
  const query = browseQuery.value.trim();
  const url = query
    ? `/api/v1/files?limit=25&q=${encodeURIComponent(query)}`
    : "/api/v1/files?limit=25";
  try {
    const body = await fetchJson(url, undefined, "Browse failed");
    renderBrowseResults(body.files || []);
  } catch (error) {
    browseResults.innerHTML = `<p>${escapeHtml(error.message)}</p>`;
  }
}

function renderBrowseResults(files) {
  if (!files.length) {
    browseResults.innerHTML = "<p>No records found.</p>";
    return;
  }

  browseResults.innerHTML = files
    .map((file) => {
      const name = file.display_name || `UFID ${file.id}`;
      const summary = [
        file.content_type,
        file.size_bytes ? formatBytes(file.size_bytes) : null,
        file.description,
        `${(file.metadata || []).length} metadata`,
        `${(file.archive_members || []).length} archive items`,
        `${(file.identity_conflicts || []).length} warnings`,
      ]
        .filter(Boolean)
        .join(" - ");
      return `
        <article class="browse-item">
          <div>
            <strong>${escapeHtml(name)}</strong>
            <span>${escapeHtml(summary || "No description")}</span>
          </div>
          <button type="button" data-file-id="${escapeHtml(file.id)}">Open</button>
        </article>
      `;
    })
    .join("");
}

function renderRecord(record) {
  if (!record) {
    recordDetails.innerHTML = "<p>No record loaded.</p>";
    return;
  }

  recordDetails.innerHTML = `
    <div class="detail-group">
      <h3>Identity</h3>
      <dl class="kv"><dt>UFID</dt><dd>${escapeHtml(record.id)}</dd></dl>
      <dl class="kv"><dt>Name</dt><dd>${escapeHtml(record.display_name || "")}</dd></dl>
      <dl class="kv"><dt>Size</dt><dd>${escapeHtml(formatBytes(record.size_bytes || 0))}</dd></dl>
      <dl class="kv"><dt>Type</dt><dd>${escapeHtml(record.content_type || "")}</dd></dl>
      <dl class="kv"><dt>Description</dt><dd>${escapeHtml(record.description || "")}</dd></dl>
    </div>
    <div class="detail-group">
      <h3>Hashes</h3>
      ${renderKeyValues(record.hashes || {})}
    </div>
    <div class="detail-group">
      <h3>Metadata</h3>
      ${renderMetadata(record.metadata || [])}
    </div>
    <div class="detail-group">
      <h3>Archive Contents</h3>
      ${renderArchiveMembers(record.archive_members || [])}
    </div>
    <div class="detail-group">
      <h3>Identity Warnings</h3>
      ${renderIdentityConflicts(record.identity_conflicts || [])}
    </div>
  `;
}

function renderMetadata(metadata) {
  if (!metadata.length) {
    return "<p>None.</p>";
  }

  return metadata
    .map(
      (item) => {
        const className = item.name === "archive_error" ? "kv warning-row" : "kv";
        return `
        <dl class="${className}">
          <dt>${escapeHtml(item.name)}<span class="meta-type">${escapeHtml(item.metadata_type)}</span></dt>
          <dd>${escapeHtml(item.value)}${item.notes ? `<span class="meta-notes">${escapeHtml(item.notes)}</span>` : ""}</dd>
        </dl>
      `;
      },
    )
    .join("");
}

function renderArchiveMembers(members) {
  if (!members.length) {
    return "<p>None.</p>";
  }

  return members
    .map((item) => {
      const child = item.child_file_id
        ? `<button class="link-button" type="button" data-file-id="${escapeHtml(item.child_file_id)}">UFID ${escapeHtml(item.child_file_id)}</button>`
        : "Empty directory";
      return `
        <dl class="kv archive-member">
          <dt>${child}</dt>
          <dd>${escapeHtml(item.archive_path || "(no archive path)")}</dd>
        </dl>
      `;
    })
    .join("");
}

function renderIdentityConflicts(conflicts) {
  if (!conflicts.length) {
    return "<p>None.</p>";
  }

  return conflicts
    .map((item) => {
      const related = item.related_file_id
        ? `<button class="link-button" type="button" data-file-id="${escapeHtml(item.related_file_id)}">UFID ${escapeHtml(item.related_file_id)}</button>`
        : "";
      return `
        <dl class="kv warning-row">
          <dt>${escapeHtml(item.conflict_type)}<span class="meta-type">${escapeHtml(item.algorithm)}</span></dt>
          <dd>
            ${related}
            <span>${escapeHtml(item.existing_value || "")} -> ${escapeHtml(item.incoming_value || "")}</span>
            ${item.notes ? `<span class="meta-notes">${escapeHtml(item.notes)}</span>` : ""}
          </dd>
        </dl>
      `;
    })
    .join("");
}

function renderKeyValues(values) {
  const entries = Object.entries(values);
  if (!entries.length) {
    return "<p>None.</p>";
  }
  return entries
    .map(
      ([key, value]) => `
        <dl class="kv">
          <dt>${escapeHtml(key)}</dt>
          <dd>${escapeHtml(value)}</dd>
        </dl>
      `,
    )
    .join("");
}

function collectMetadataPayload() {
  const rows = [...state.metadataRows];
  const draft = readMetadataDraft({ requireRow: false });
  if (draft && !metadataRowExists(draft, rows)) {
    rows.push(draft);
  }
  return rows;
}

function readMetadataDraft({ requireRow }) {
  const metadataType = metadataTypeInput.value;
  const name = metadataNameInput.value.trim();
  const value = metadataValueInput.value.trim();
  const notes = metadataNotesInput.value.trim();
  const hasDraft = Boolean(name || value || notes);
  if (!hasDraft) {
    if (requireRow) {
      setRecordState("Enter metadata before adding it", "warn");
      throw new Error("empty metadata row");
    }
    return null;
  }
  if (!name) {
    setRecordState("Metadata name is required", "warn");
    throw new Error("metadata name is required");
  }
  if (!value) {
    setRecordState("Metadata value is required", "warn");
    throw new Error("metadata value is required");
  }
  return {
    metadata_type: metadataType,
    name,
    value,
    notes: notes || null,
  };
}

function metadataRowExists(row, rows = state.metadataRows) {
  return rows.some(
    (item) =>
      item.metadata_type === row.metadata_type &&
      item.name === row.name &&
      item.value === row.value &&
      (item.notes || "") === (row.notes || ""),
  );
}

function clearMetadataDraft() {
  metadataTypeInput.value = "text";
  metadataNameInput.value = "";
  metadataValueInput.value = "";
  metadataNotesInput.value = "";
}

function renderMetadataDraftList() {
  if (!state.metadataRows.length) {
    metadataDraftList.innerHTML = "<p>No extra metadata staged.</p>";
    return;
  }

  metadataDraftList.innerHTML = state.metadataRows
    .map(
      (item, index) => `
        <article class="metadata-draft-item">
          <div>
            <strong>${escapeHtml(item.name)}</strong>
            <span>${escapeHtml(item.metadata_type)} - ${escapeHtml(item.value)}</span>
            ${item.notes ? `<small>${escapeHtml(item.notes)}</small>` : ""}
          </div>
          <button type="button" class="secondary-button" data-metadata-index="${index}">Remove</button>
        </article>
      `,
    )
    .join("");
}

function setRecordState(message, type) {
  recordState.textContent = message;
  recordState.className = `status ${type}`;
}

async function checkApi() {
  try {
    await fetchJson("/health", undefined, "API unavailable");
    apiStatus.textContent = "API online";
    apiStatus.className = "status ok";
    await loadSession();
    await browseFiles();
  } catch {
    apiStatus.textContent = "API offline";
    apiStatus.className = "status error";
  }
}

async function login() {
  const username = loginUsername.value.trim();
  const password = loginPassword.value;
  if (!username || !password) {
    setRecordState("Enter username and password", "warn");
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
    updateActionState();
    setRecordState(`Logged in as ${state.user.username}`, "ok");
    await browseFiles();
  } catch (error) {
    setRecordState(error.message, "error");
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
  renderSession();
  updateActionState();
  browseResults.innerHTML = "<p>Log in to browse records.</p>";
  renderRecord(null);
  setRecordState("Logged out", "quiet");
}

async function loadSession() {
  try {
    const body = await fetchJson("/api/v1/auth/session", undefined, "Session check failed");
    state.user = body.authenticated ? body.user : null;
  } catch {
    state.user = null;
  }
  renderSession();
  updateActionState();
}

function renderSession() {
  const authenticated = Boolean(state.user);
  loginForm.hidden = authenticated;
  sessionPanel.hidden = !authenticated;
  if (authenticated) {
    const roles = (state.user.roles || []).join(", ");
    sessionUser.textContent = `${state.user.username}${roles ? ` (${roles})` : ""}`;
  } else {
    sessionUser.textContent = "";
  }
}

function updateActionState() {
  const authenticated = Boolean(state.user);
  const hasHashes = Boolean(state.hashes.sha1);
  searchButton.disabled = !authenticated || !hasHashes;
  addButton.disabled = !authenticated || !hasHashes;
  browseButton.disabled = !authenticated;
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
        throw new Error(`${fallbackMessage}: ${httpErrorSummary(response, text)}`);
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

function crc32Hex(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ byte) & 0xff];
  }
  return ((crc ^ 0xffffffff) >>> 0).toString(16).padStart(8, "0");
}

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[index] = value >>> 0;
  }
  return table;
})();

function md5Hex(bytes) {
  const originalLength = bytes.length;
  const paddedLength = (((originalLength + 8) >>> 6) + 1) << 6;
  const padded = new Uint8Array(paddedLength);
  padded.set(bytes);
  padded[originalLength] = 0x80;

  const bitLength = BigInt(originalLength) * 8n;
  for (let index = 0; index < 8; index += 1) {
    padded[paddedLength - 8 + index] = Number((bitLength >> BigInt(8 * index)) & 0xffn);
  }

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;

  for (let offset = 0; offset < padded.length; offset += 64) {
    const words = new Uint32Array(16);
    for (let index = 0; index < 16; index += 1) {
      const base = offset + index * 4;
      words[index] =
        padded[base] |
        (padded[base + 1] << 8) |
        (padded[base + 2] << 16) |
        (padded[base + 3] << 24);
    }

    let a = a0;
    let b = b0;
    let c = c0;
    let d = d0;

    for (let i = 0; i < 64; i += 1) {
      let f;
      let g;
      if (i < 16) {
        f = (b & c) | (~b & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | (~d & c);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) % 16;
      } else {
        f = c ^ (b | ~d);
        g = (7 * i) % 16;
      }

      const next = d;
      d = c;
      c = b;
      b = add32(
        b,
        leftRotate(add32(add32(a, f), add32(MD5_K[i], words[g])), MD5_S[i]),
      );
      a = next;
    }

    a0 = add32(a0, a);
    b0 = add32(b0, b);
    c0 = add32(c0, c);
    d0 = add32(d0, d);
  }

  return [a0, b0, c0, d0].map(wordToHex).join("");
}

function add32(left, right) {
  return (left + right) >>> 0;
}

function leftRotate(value, shift) {
  return ((value << shift) | (value >>> (32 - shift))) >>> 0;
}

function wordToHex(word) {
  return [0, 8, 16, 24]
    .map((shift) => ((word >>> shift) & 0xff).toString(16).padStart(2, "0"))
    .join("");
}

const MD5_S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const MD5_K = Array.from({ length: 64 }, (_, index) =>
  Math.floor(Math.abs(Math.sin(index + 1)) * 2 ** 32) >>> 0,
);
