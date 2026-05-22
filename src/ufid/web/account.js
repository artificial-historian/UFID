const state = {
  user: null,
  profile: null,
  removalRequest: null,
  users: [],
  removalRequests: [],
  registrationToken: new URLSearchParams(window.location.search).get("registration_token") || "",
};

const USER_ROLES = ["reader", "contributor", "curator", "admin"];

const accountState = document.querySelector("#accountState");
const adminPanel = document.querySelector("#adminPanel");
const adminState = document.querySelector("#adminState");
const apiStatus = document.querySelector("#apiStatus");
const changePasswordButton = document.querySelector("#changePasswordButton");
const completeRegistrationButton = document.querySelector("#completeRegistrationButton");
const createUserButton = document.querySelector("#createUserButton");
const createUserForm = document.querySelector("#createUserForm");
const currentPassword = document.querySelector("#currentPassword");
const invitationForm = document.querySelector("#invitationForm");
const inviteDisplayName = document.querySelector("#inviteDisplayName");
const invitePassword = document.querySelector("#invitePassword");
const inviteUsername = document.querySelector("#inviteUsername");
const loginButton = document.querySelector("#loginButton");
const loginForm = document.querySelector("#loginForm");
const loginPassword = document.querySelector("#loginPassword");
const loginUsername = document.querySelector("#loginUsername");
const logoutButton = document.querySelector("#logoutButton");
const newPassword = document.querySelector("#newPassword");
const newUserDisplayName = document.querySelector("#newUserDisplayName");
const newUserUsername = document.querySelector("#newUserUsername");
const passwordForm = document.querySelector("#passwordForm");
const profileDetails = document.querySelector("#profileDetails");
const profilePanel = document.querySelector("#profilePanel");
const publicAccountPanel = document.querySelector("#publicAccountPanel");
const refreshAdminButton = document.querySelector("#refreshAdminButton");
const registerButton = document.querySelector("#registerButton");
const registerDisplayName = document.querySelector("#registerDisplayName");
const registerPassword = document.querySelector("#registerPassword");
const registerUsername = document.querySelector("#registerUsername");
const registrationForm = document.querySelector("#registrationForm");
const registrationLinkResult = document.querySelector("#registrationLinkResult");
const removalRequestsTable = document.querySelector("#removalRequestsTable");
const requestRemovalButton = document.querySelector("#requestRemovalButton");
const sessionPanel = document.querySelector("#sessionPanel");
const sessionUser = document.querySelector("#sessionUser");
const usersTable = document.querySelector("#usersTable");

checkApi();

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await login();
});

logoutButton.addEventListener("click", async () => {
  await logout();
});

registrationForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await register();
});

invitationForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await completeRegistration();
});

passwordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await changePassword();
});

requestRemovalButton.addEventListener("click", async () => {
  await requestRemoval();
});

createUserForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await createUser();
});

refreshAdminButton.addEventListener("click", async () => {
  await loadAdminData();
});

usersTable.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-user-action]");
  if (!button) {
    return;
  }
  await runUserAction(Number(button.dataset.userId), button.dataset.userAction);
});

removalRequestsTable.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-removal-action]");
  if (!button) {
    return;
  }
  await runRemovalAction(Number(button.dataset.requestId), button.dataset.removalAction);
});

registrationLinkResult.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-copy-link]");
  if (!button) {
    return;
  }
  try {
    await navigator.clipboard.writeText(button.dataset.copyLink || "");
    setAdminState("Link copied", "ok");
  } catch {
    setAdminState("Copy failed", "warn");
  }
});

async function checkApi() {
  try {
    await fetchJson("/health", undefined, "API unavailable");
    apiStatus.textContent = "API online";
    apiStatus.className = "status ok";
  } catch {
    apiStatus.textContent = "API offline";
    apiStatus.className = "status error";
    setAccountState("API offline", "error");
    return;
  }

  if (state.registrationToken) {
    await validateRegistrationToken();
  }
  await loadSession();
  if (state.user) {
    await loadProfile();
  } else {
    renderAccount();
  }
}

async function validateRegistrationToken() {
  try {
    const body = await fetchJson(
      `/api/v1/auth/registration/validate?token=${encodeURIComponent(state.registrationToken)}`,
      undefined,
      "Link check failed",
    );
    const user = body.registration?.user || {};
    inviteUsername.value = user.username || "";
    inviteDisplayName.value = user.display_name || "";
    invitationForm.hidden = false;
    setAccountState("Registration link ready", "ok");
  } catch (error) {
    invitationForm.hidden = false;
    completeRegistrationButton.disabled = true;
    setAccountState(error.message, "error");
  }
}

async function login() {
  const username = loginUsername.value.trim();
  const password = loginPassword.value;
  if (!username || !password) {
    setAccountState("Enter username and password", "warn");
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
    setAccountState(`Logged in as ${state.user.username}`, "ok");
    await loadProfile();
  } catch (error) {
    setAccountState(error.message, "error");
  } finally {
    loginButton.disabled = false;
    renderAccount();
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
    // The visible account state can still be cleared after an expired session.
  }
  state.user = null;
  state.profile = null;
  state.removalRequest = null;
  state.users = [];
  state.removalRequests = [];
  setAccountState("Logged out", "quiet");
  renderAccount();
}

async function loadSession() {
  try {
    const body = await fetchJson("/api/v1/auth/session", undefined, "Session check failed");
    state.user = body.authenticated ? body.user : null;
  } catch {
    state.user = null;
  }
  renderAccount();
}

async function loadProfile() {
  if (!state.user) {
    renderAccount();
    return;
  }
  try {
    const body = await fetchJson("/api/v1/auth/me", undefined, "Profile load failed");
    state.profile = body.user;
    state.removalRequest = body.removal_request;
    renderAccount();
    if (isAdmin()) {
      await loadAdminData();
    }
  } catch (error) {
    setAccountState(error.message, "error");
  }
}

async function register() {
  registerButton.disabled = true;
  try {
    const body = await fetchJson("/api/v1/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: registerUsername.value.trim(),
        display_name: registerDisplayName.value.trim() || null,
        password: registerPassword.value,
      }),
    }, "Registration failed");
    registrationForm.reset();
    setAccountState(`${body.user.username} registered`, "ok");
  } catch (error) {
    setAccountState(error.message, "error");
  } finally {
    registerButton.disabled = false;
  }
}

async function completeRegistration() {
  if (!state.registrationToken) {
    setAccountState("Registration token missing", "warn");
    return;
  }
  completeRegistrationButton.disabled = true;
  try {
    const body = await fetchJson("/api/v1/auth/registration/complete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        token: state.registrationToken,
        display_name: inviteDisplayName.value.trim() || null,
        password: invitePassword.value,
      }),
    }, "Registration failed");
    state.user = body.user;
    state.registrationToken = "";
    window.history.replaceState({}, document.title, "/account.html");
    invitePassword.value = "";
    setAccountState("Registration complete", "ok");
    await loadProfile();
  } catch (error) {
    setAccountState(error.message, "error");
  } finally {
    completeRegistrationButton.disabled = false;
  }
}

async function changePassword() {
  changePasswordButton.disabled = true;
  try {
    await fetchJson("/api/v1/auth/me/password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        current_password: currentPassword.value,
        new_password: newPassword.value,
      }),
    }, "Password change failed");
    passwordForm.reset();
    setAccountState("Password changed", "ok");
  } catch (error) {
    setAccountState(error.message, "error");
  } finally {
    changePasswordButton.disabled = false;
  }
}

async function requestRemoval() {
  if (state.removalRequest?.status === "pending") {
    setAccountState("Removal already requested", "warn");
    return;
  }
  const confirmed = window.confirm("Request account removal?");
  if (!confirmed) {
    return;
  }
  requestRemovalButton.disabled = true;
  try {
    const body = await fetchJson("/api/v1/auth/me/removal-request", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    }, "Removal request failed");
    state.removalRequest = body.request;
    setAccountState("Removal requested", "ok");
    renderProfile();
  } catch (error) {
    setAccountState(error.message, "error");
  } finally {
    requestRemovalButton.disabled = false;
  }
}

async function createUser() {
  createUserButton.disabled = true;
  try {
    const roles = [...document.querySelectorAll('input[name="newUserRole"]:checked')]
      .map((input) => input.value);
    const body = await fetchJson("/api/v1/auth/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: newUserUsername.value.trim(),
        display_name: newUserDisplayName.value.trim() || null,
        roles,
      }),
    }, "User creation failed");
    createUserForm.reset();
    document.querySelector('input[name="newUserRole"][value="reader"]').checked = true;
    renderRegistrationLink(body.registration);
    setAdminState(`Created ${body.user.username}`, "ok");
    await loadAdminData();
  } catch (error) {
    setAdminState(error.message, "error");
  } finally {
    createUserButton.disabled = false;
  }
}

async function loadAdminData() {
  if (!isAdmin()) {
    adminPanel.hidden = true;
    return;
  }
  refreshAdminButton.disabled = true;
  try {
    const [usersBody, removalBody] = await Promise.all([
      fetchJson("/api/v1/auth/users", undefined, "Users load failed"),
      fetchJson("/api/v1/auth/removal-requests?status=pending", undefined, "Requests load failed"),
    ]);
    state.users = usersBody.users || [];
    state.removalRequests = removalBody.requests || [];
    renderAdmin();
    setAdminState(`${state.users.length} users`, "ok");
  } catch (error) {
    setAdminState(error.message, "error");
  } finally {
    refreshAdminButton.disabled = false;
  }
}

async function runUserAction(userId, action) {
  if (action === "delete" && !window.confirm("Remove this user completely?")) {
    return;
  }
  try {
    let body;
    if (action === "delete") {
      body = await fetchJson(`/api/v1/auth/users/${userId}`, {
        method: "DELETE",
      }, "Delete failed");
      setAdminState(`Deleted user ${body.user_id}`, "ok");
    } else if (action === "roles") {
      const roles = selectedRolesForUser(userId);
      body = await fetchJson(`/api/v1/auth/users/${userId}/roles`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ roles }),
      }, "Role update failed");
      setAdminState(`${body.user.username} roles updated`, "ok");
    } else {
      body = await fetchJson(`/api/v1/auth/users/${userId}/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      }, "User update failed");
      if (body.registration) {
        renderRegistrationLink(body.registration);
        setAdminState("Registration link created", "ok");
      } else {
        setAdminState(`${body.user.username} updated`, "ok");
      }
    }
    await loadAdminData();
  } catch (error) {
    setAdminState(error.message, "error");
  }
}

async function runRemovalAction(requestId, action) {
  if (action === "approve" && !window.confirm("Approve removal and delete this user?")) {
    return;
  }
  try {
    await fetchJson(`/api/v1/auth/removal-requests/${requestId}/${action}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    }, "Request update failed");
    setAdminState(action === "approve" ? "Removal approved" : "Removal blocked", "ok");
    await loadAdminData();
  } catch (error) {
    setAdminState(error.message, "error");
  }
}

function renderAccount() {
  const authenticated = Boolean(state.user);
  loginForm.hidden = authenticated;
  sessionPanel.hidden = !authenticated;
  publicAccountPanel.hidden = authenticated;
  profilePanel.hidden = !authenticated;
  adminPanel.hidden = !isAdmin();

  if (authenticated) {
    const roles = (state.user.roles || []).join(", ");
    sessionUser.textContent = `${state.user.username}${roles ? ` (${roles})` : ""}`;
  } else {
    sessionUser.textContent = "";
  }

  renderProfile();
  renderAdmin();
}

function renderProfile() {
  if (!state.profile) {
    profileDetails.innerHTML = "<p>No profile loaded.</p>";
    requestRemovalButton.disabled = true;
    return;
  }
  const user = state.profile;
  const roles = (user.roles || []).join(", ");
  const removal = state.removalRequest;
  profileDetails.innerHTML = `
    <dl class="kv"><dt>Username</dt><dd>${escapeHtml(user.username)}</dd></dl>
    <dl class="kv"><dt>Display name</dt><dd>${escapeHtml(user.display_name || "")}</dd></dl>
    <dl class="kv"><dt>Status</dt><dd>${escapeHtml(statusLabel(user.status))}</dd></dl>
    <dl class="kv"><dt>Roles</dt><dd>${escapeHtml(roles || "reader")}</dd></dl>
    <dl class="kv"><dt>Created</dt><dd>${escapeHtml(formatDate(user.created_at))}</dd></dl>
    <dl class="kv"><dt>Removal</dt><dd>${escapeHtml(removal ? statusLabel(removal.status) : "None")}</dd></dl>
  `;
  requestRemovalButton.disabled = removal?.status === "pending";
}

function renderAdmin() {
  if (!isAdmin()) {
    return;
  }
  usersTable.innerHTML = state.users.length
    ? state.users.map(renderUserRow).join("")
    : '<tr><td colspan="5">No users found.</td></tr>';
  removalRequestsTable.innerHTML = state.removalRequests.length
    ? state.removalRequests.map(renderRemovalRequestRow).join("")
    : '<tr><td colspan="4">No pending removal requests.</td></tr>';
}

function renderUserRow(user) {
  const isSelf = state.user && user.id === state.user.id;
  const active = user.status === "active";
  return `
    <tr>
      <td>
        <strong>${escapeHtml(user.username)}</strong>
        ${user.display_name ? `<span class="meta-type">${escapeHtml(user.display_name)}</span>` : ""}
      </td>
      <td>${escapeHtml(statusLabel(user.status))}</td>
      <td>${renderRoleControls(user, isSelf)}</td>
      <td>${escapeHtml(formatDate(user.created_at))}</td>
      <td>
        <div class="table-actions">
          <button class="secondary-button" type="button" data-user-id="${user.id}" data-user-action="roles">Save Roles</button>
          <button class="secondary-button" type="button" data-user-id="${user.id}" data-user-action="${active ? "deactivate" : "activate"}" ${isSelf && active ? "disabled" : ""}>${active ? "Deactivate" : "Activate"}</button>
          <button class="secondary-button" type="button" data-user-id="${user.id}" data-user-action="invite">Link</button>
          <button class="danger-button" type="button" data-user-id="${user.id}" data-user-action="delete" ${isSelf ? "disabled" : ""}>Delete</button>
        </div>
      </td>
    </tr>
  `;
}

function renderRoleControls(user, isSelf) {
  const assigned = new Set(user.roles || []);
  const roles = USER_ROLES.map((role) => {
    const checked = assigned.has(role) ? "checked" : "";
    const disabled = isSelf && role === "admin" ? "disabled" : "";
    return `<label><input type="checkbox" data-role-input value="${role}" ${checked} ${disabled}> ${escapeHtml(statusLabel(role))}</label>`;
  }).join("");
  return `<div class="table-role-grid" data-role-user-id="${user.id}">${roles}</div>`;
}

function selectedRolesForUser(userId) {
  const controls = usersTable.querySelector(`[data-role-user-id="${userId}"]`);
  if (!controls) {
    throw new Error("Role controls not found");
  }
  const roles = [...controls.querySelectorAll("input[data-role-input]:checked")]
    .map((input) => input.value);
  if (roles.length === 0) {
    throw new Error("Select at least one role");
  }
  return roles;
}

function renderRemovalRequestRow(request) {
  const user = request.user || {};
  return `
    <tr>
      <td>
        <strong>${escapeHtml(user.username || `User ${request.user_id}`)}</strong>
        ${user.display_name ? `<span class="meta-type">${escapeHtml(user.display_name)}</span>` : ""}
      </td>
      <td>${escapeHtml(formatDate(request.requested_at))}</td>
      <td>${escapeHtml(statusLabel(request.status))}</td>
      <td>
        <div class="table-actions">
          <button class="danger-button" type="button" data-request-id="${request.id}" data-removal-action="approve">Approve</button>
          <button class="secondary-button" type="button" data-request-id="${request.id}" data-removal-action="block">Block</button>
        </div>
      </td>
    </tr>
  `;
}

function renderRegistrationLink(registration) {
  if (!registration?.completion_url) {
    registrationLinkResult.innerHTML = "<p>No link generated.</p>";
    return;
  }
  registrationLinkResult.innerHTML = `
    <label>
      Link
      <input type="text" readonly value="${escapeHtml(registration.completion_url)}">
    </label>
    <button class="secondary-button" type="button" data-copy-link="${escapeHtml(registration.completion_url)}">Copy</button>
    <p>Expires ${escapeHtml(formatDate(registration.expires_at))}</p>
  `;
}

function isAdmin() {
  return Boolean(state.user?.roles?.includes("admin"));
}

function setAccountState(message, type = "quiet") {
  accountState.textContent = message;
  accountState.className = `status ${type}`;
}

function setAdminState(message, type = "quiet") {
  adminState.textContent = message;
  adminState.className = `status ${type}`;
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
    throw new Error(body.error || failureMessage || `HTTP ${response.status}`);
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

function statusLabel(value) {
  return String(value || "")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatDate(value) {
  if (!value) {
    return "";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }
  return date.toLocaleString();
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
