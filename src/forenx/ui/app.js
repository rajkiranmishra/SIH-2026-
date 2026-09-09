"use strict";

const state = {
  token: sessionStorage.getItem("forenx.session"),
  user: null,
  expiresAt: Number(sessionStorage.getItem("forenx.expires")) || 0,
  lastActivity: Number(sessionStorage.getItem("forenx.activity")) || 0,
  browserSession: sessionStorage.getItem("forenx.browser-session"),
  idleTimeoutMs: 30 * 60 * 1000,
  cases: [],
  selectedCase: null,
  selectedExhibits: [],
  selectedEvidenceSources: [],
  caseUsers: [],
  caseAssignments: [],
  biometricAuthorizations: [],
  selectedEvidence: null,
  currentInspection: null,
  currentFaceDetections: [],
  currentFaceTrackingRuns: [],
  currentBiometricAuthorizations: [],
  selectedRecoverySource: null,
  currentRecoveryScans: [],
  recoveryArtifactsByScan: new Map(),
  trackStartTimestampMs: 0,
  trackEndTimestampMs: 0,
  bookmarkTimestampMs: 0,
};

const rolePermissions = {
  "intake-officer": new Set([
    "case:create",
    "case:read",
    "exhibit:create",
    "evidence:ingest",
  ]),
  examiner: new Set(["case:read", "case:process"]),
  supervisor: new Set([
    "case:read",
    "case:assign",
    "case:process",
    "case:approve",
    "biometric:authorize",
  ]),
  investigator: new Set(["case:read"]),
  auditor: new Set(["case:read"]),
  administrator: new Set([
    "case:create",
    "case:read",
    "case:assign",
    "exhibit:create",
    "evidence:ingest",
    "case:process",
    "case:approve",
    "biometric:authorize",
    "user:manage",
  ]),
};

const caseTransitions = {
  intake: ["acquisition"],
  acquisition: ["processing", "intake"],
  processing: ["examiner-review", "acquisition"],
  "examiner-review": ["supervisor-review", "processing"],
  "supervisor-review": ["approved", "examiner-review"],
  approved: ["closed", "examiner-review"],
  closed: [],
};

const actionLabels = {
  CASE_CREATED: "Case registered",
  CASE_ACCESS_GRANTED: "Case access granted",
  CASE_ACCESS_REVOKED: "Case access revoked",
  EXHIBIT_REGISTERED: "Exhibit registered",
  CASE_STATUS_CHANGED: "Workflow stage changed",
  EVIDENCE_INGEST_STARTED: "Evidence intake started",
  EVIDENCE_INGEST_COMPLETED: "Evidence intake completed",
  EVIDENCE_INGEST_FAILED: "Evidence intake failed",
  EVIDENCE_INTEGRITY_VERIFIED: "Evidence integrity verified",
  EVIDENCE_INTEGRITY_FAILED: "Evidence integrity warning",
  RECOVERY_SCAN_STARTED: "Vendor recovery scan started",
  RECOVERY_SCAN_FAILED: "Vendor recovery scan failed",
  RECOVERY_SCAN_COMPLETED: "Vendor recovery scan completed",
  RECOVERY_EXTRACTION_STARTED: "Recording extraction started",
  RECOVERY_EXTRACTION_FAILED: "Recording extraction failed",
  RECOVERY_EXTRACTION_COMPLETED: "Recording extracted and verified",
  RECOVERY_ARTIFACT_REGISTRATION_STARTED: "Recovered stream registration started",
  RECOVERY_ARTIFACT_REGISTRATION_FAILED: "Recovered stream registration failed",
  RECOVERY_ARTIFACT_REGISTERED: "Recovered stream registered for examination",
  MEDIA_INSPECTED: "Video metadata inspected",
  MEDIA_INSPECTION_FAILED: "Video inspection failed",
  MEDIA_BOOKMARK_CREATED: "Examiner bookmark created",
  BIOMETRIC_ANALYSIS_AUTHORIZED: "Controlled face analysis authorized",
  FACE_DETECTION_STARTED: "Face detection started",
  FACE_DETECTION_FAILED: "Face detection failed",
  FACE_DETECTION_COMPLETED: "Face detection completed",
  FACE_TRACKING_STARTED: "Geometric face tracking started",
  FACE_TRACKING_FAILED: "Geometric face tracking failed",
  FACE_TRACKING_COMPLETED: "Geometric face tracking completed",
  REPORT_EXPORT_STARTED: "Signed report export started",
  REPORT_EXPORT_FAILED: "Signed report export failed",
  REPORT_PACKAGE_CREATED: "Signed report package created",
};

const authView = document.querySelector("#auth-view");
const workspace = document.querySelector("#workspace");
const loginForm = document.querySelector("#login-form");
const setupForm = document.querySelector("#setup-form");
const caseRows = document.querySelector("#case-rows");
const emptyCases = document.querySelector("#empty-cases");
const caseCreateDialog = document.querySelector("#case-create-dialog");
const caseCreateForm = document.querySelector("#case-create-form");
const caseDetailDialog = document.querySelector("#case-detail-dialog");
const exhibitDialog = document.querySelector("#exhibit-dialog");
const exhibitForm = document.querySelector("#exhibit-form");
const evidenceDialog = document.querySelector("#evidence-dialog");
const evidenceForm = document.querySelector("#evidence-form");
const recoveryDialog = document.querySelector("#recovery-dialog");
const videoDialog = document.querySelector("#video-dialog");
const evidencePlayer = document.querySelector("#evidence-player");
const bookmarkDialog = document.querySelector("#bookmark-dialog");
const bookmarkForm = document.querySelector("#bookmark-form");
const faceDetectionDialog = document.querySelector("#face-detection-dialog");
const reportDialog = document.querySelector("#report-dialog");
const reportForm = document.querySelector("#report-form");
const biometricAuthorizationDialog = document.querySelector(
  "#biometric-authorization-dialog",
);
const biometricAuthorizationForm = document.querySelector(
  "#biometric-authorization-form",
);
const transitionForm = document.querySelector("#transition-form");
const caseTeamForm = document.querySelector("#case-team-form");
const userAdminDialog = document.querySelector("#user-admin-dialog");
const userCreateForm = document.querySelector("#user-create-form");
const vendorDialog = document.querySelector("#vendor-dialog");
const capabilityDialog = document.querySelector("#capability-dialog");
const toast = document.querySelector("#toast");
const requiredPasswordForm = document.querySelector("#required-password-form");
const passwordForm = document.querySelector("#password-form");
const accountDialog = document.querySelector("#account-dialog");
const userActionForm = document.querySelector("#user-action-form");
const userActionDialog = document.querySelector("#user-action-dialog");
let sessionGeneration = 0;
const requests = new Set();
let sessionTimer = null;
let activityRequestAt = 0;
let pendingLogout = null;
let logoutInFlight = false;
let selectedUserAction = null;
let authHistoryCursors = [null];
let authHistoryNext = null;
let authHistoryBusy = false;
const authUserNames = new Map();
const sessionChannel = typeof BroadcastChannel === "function"
  ? new BroadcastChannel("forenx-session") : null;
sessionStorage.removeItem("forenx.user"); // Display permissions always come from /auth/me.

function assertSession(generation) {
  if (generation !== sessionGeneration) {
    throw new DOMException("Session changed. Sign in again.", "AbortError");
  }
}

function invalidateRequests() {
  sessionGeneration += 1;
  for (const controller of requests) controller.abort();
  requests.clear();
}

async function request(path, options = {}, resultType = "json") {
  const publicRequest = path.startsWith("/api/v1/setup") || path === "/api/v1/auth/login";
  const generation = sessionGeneration;
  if (!publicRequest && !state.token) {
    throw new DOMException("Session changed. Sign in again.", "AbortError");
  }
  const controller = new AbortController();
  requests.add(controller);
  const headers = new Headers(options.headers || {});
  if (typeof options.body === "string" && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (state.token && !publicRequest) headers.set("Authorization", `Bearer ${state.token}`);
  try {
    const response = await fetch(path, { ...options, headers, signal: controller.signal });
    assertSession(generation);
    if (response.ok) {
      const expiry = response.headers.get("X-Session-Expires-At");
      if (expiry && !publicRequest) {
        const expiresAt = Date.parse(expiry);
        if (Number.isFinite(expiresAt)) {
          state.expiresAt = expiresAt;
          sessionStorage.setItem("forenx.expires", String(expiresAt));
        }
      }
      const payload = response.status === 204 ? null
        : resultType === "blob" ? await response.blob() : await response.json();
      assertSession(generation);
      return payload;
    }
    const payload = await response.json().catch(() => ({}));
    assertSession(generation);
    const details = Array.isArray(payload.detail)
      ? payload.detail.map((item) => item.msg).join("; ") : payload.detail;
    const error = new Error(details || "The operation could not be completed");
    error.status = response.status;
    if (response.status === 429) {
      const delay = response.headers.get("Retry-After");
      error.message += delay ? ` Try again in ${delay} seconds.` : " Please wait before trying again.";
    }
    if (!publicRequest && response.status === 401) {
      showAuth(true, "Your session is no longer valid. Sign in again to continue.");
    } else if (!publicRequest && response.status === 403 && details === "Password change required") {
      if (state.user) state.user.must_change_password = true;
      showPasswordGate();
    }
    throw error;
  } finally {
    requests.delete(controller);
  }
}

async function api(path, options = {}) {
  return request(path, options);
}

function can(permission) {
  return Boolean(state.token && !state.user?.must_change_password
    && rolePermissions[state.user?.role]?.has(permission));
}

function formPayload(form) {
  return Object.fromEntries(
    [...new FormData(form).entries()].filter(([, value]) => value !== ""),
  );
}

function exhibitPayload(form) {
  const payload = formPayload(form);
  for (const field of ["channel_count", "working_channels_observed", "clock_offset_seconds"]) {
    if (payload[field] !== undefined) payload[field] = Number(payload[field]);
  }
  for (const field of ["collected_at", "recorder_time_observed"]) {
    if (payload[field]) payload[field] = new Date(payload[field]).toISOString();
  }
  return payload;
}

function setBusy(form, busy) {
  const button = form.querySelector("button[type='submit']");
  button.disabled = busy;
  button.setAttribute("aria-busy", String(busy));
}

function showToast(message) {
  toast.textContent = message;
  toast.hidden = false;
  window.setTimeout(() => {
    toast.hidden = true;
  }, 3500);
}

function clearPrivateWorkspace() {
  for (const dialog of document.querySelectorAll("dialog[open]")) dialog.close();
  for (const media of document.querySelectorAll("video, audio")) {
    media.pause();
    media.removeAttribute("src");
    media.load();
  }
  document.querySelector("#face-detection-image").removeAttribute("src");
  document.querySelector("#face-detection-overlay").replaceChildren();
  for (const form of document.querySelectorAll("form")) form.reset();
  for (const input of document.querySelectorAll("input[type='password']")) input.value = "";
  for (const element of document.querySelectorAll(
    "#case-rows, [id$='-list'], #case-team-user, #evidence-exhibit, #report-source, #biometric-source, #transition-target, #capability-body",
  )) element.replaceChildren();
  for (const id of [
    "user-name", "user-role", "user-avatar", "detail-reference", "detail-agency", "detail-status",
    "detail-officer", "detail-station", "detail-classification", "detail-updated", "video-title",
    "video-hash", "recovery-filename", "recovery-hash", "face-detection-title", "face-detection-subtitle",
    "detection-observed-time", "detection-frame-hash", "detection-model", "detection-model-hash",
    "detection-threshold", "detection-authorization", "media-container", "media-duration", "media-codec",
    "media-resolution", "media-frame-rate", "media-bit-rate", "account-identity", "user-action-identity",
    "auth-history-integrity", "user-count", "bookmark-count", "inspection-tool",
  ]) document.getElementById(id).textContent = "";
  for (const element of document.querySelectorAll(".form-error, .report-readiness, .analysis-readiness")) {
    element.textContent = "";
  }
  for (const element of document.querySelectorAll(".metrics span")) element.textContent = "—";
  document.querySelector("#case-search").value = "";
  document.querySelector("#queue-status").textContent = "Sign in to load protected records.";
  document.querySelector("#empty-cases").hidden = true;
  document.querySelector("#player-error").hidden = true;
  toast.hidden = true;
  toast.textContent = "";
  for (const key of Object.keys(state)) {
    if (Array.isArray(state[key])) state[key] = [];
  }
  state.selectedCase = null;
  state.selectedEvidence = null;
  state.currentInspection = null;
  state.selectedRecoverySource = null;
  state.recoveryArtifactsByScan.clear();
  state.trackStartTimestampMs = 0;
  state.trackEndTimestampMs = 0;
  state.bookmarkTimestampMs = 0;
  selectedUserAction = null;
  authHistoryCursors = [null];
  authHistoryNext = null;
  authUserNames.clear();
  workspace.hidden = true;
}

function setAuthStatus(message) {
  const status = document.querySelector("#auth-status");
  status.textContent = message;
  status.hidden = !message;
}

function showAuth(initialized, message = "") {
  invalidateRequests();
  clearPrivateWorkspace();
  window.clearTimeout(sessionTimer);
  document.querySelector("#session-warning").hidden = true;
  state.token = null;
  state.user = null;
  state.expiresAt = 0;
  state.lastActivity = 0;
  state.browserSession = null;
  for (const key of ["session", "user", "expires", "activity", "browser-session"]) {
    sessionStorage.removeItem(`forenx.${key}`);
  }
  authView.hidden = false;
  loginForm.hidden = !initialized;
  setupForm.hidden = initialized;
  requiredPasswordForm.hidden = true;
  setAuthStatus(message);
}

function showPasswordGate() {
  invalidateRequests();
  clearPrivateWorkspace();
  authView.hidden = false;
  loginForm.hidden = true;
  setupForm.hidden = true;
  requiredPasswordForm.hidden = false;
  setAuthStatus("");
  requiredPasswordForm.elements.current_password.focus();
}

function broadcastSessionChange(marker) {
  try { localStorage.setItem("forenx.browser-session", marker); } catch (_error) { /* Private browsing may disable storage. */ }
  sessionChannel?.postMessage({ marker });
}

function checkBrowserSession(marker) {
  if (state.token && marker && marker !== state.browserSession) {
    showAuth(true, "The browser account session changed in another tab. Sign in again before viewing evidence.");
  }
}

async function retryLogout() {
  if (!pendingLogout || logoutInFlight) return;
  logoutInFlight = true;
  const button = document.querySelector("#retry-logout");
  button.disabled = true;
  const attempt = pendingLogout;
  try {
    const response = await fetch(attempt.path, {
      method: "POST", headers: { Authorization: `Bearer ${attempt.token}` },
    });
    if (!response.ok && response.status !== 401) throw new Error("Server sign-out was not confirmed.");
    pendingLogout = null;
    button.hidden = true;
    loginForm.querySelector("button[type='submit']").disabled = false;
    setAuthStatus(response.status === 401 && attempt.path.endsWith("/logout-all")
      ? "This session is no longer valid. Other sessions could not be revoked. Sign in again to sign out all sessions."
      : attempt.message);
  } catch (_error) {
    button.hidden = false;
    setAuthStatus("The workspace is locked on this device. Server sign-out could not be confirmed; retry when the local service is available. Keep this page open to retry.");
  } finally {
    logoutInFlight = false;
    button.disabled = false;
  }
}

async function signOut(allSessions = false, message = "Signed out. Your server session has been revoked.") {
  if (!state.token) return;
  pendingLogout = {
    token: state.token,
    path: allSessions ? "/api/v1/auth/logout-all" : "/api/v1/auth/logout",
    message,
  };
  showAuth(true, "Workspace locked. Confirming server sign-out…");
  loginForm.querySelector("button[type='submit']").disabled = true;
  broadcastSessionChange(crypto.randomUUID());
  await retryLogout();
}

function checkSessionTime() {
  window.clearTimeout(sessionTimer);
  if (!state.token) return;
  const remaining = Math.min(state.expiresAt - Date.now(), state.lastActivity + state.idleTimeoutMs - Date.now());
  if (remaining <= 0) {
    void signOut(false, "Your session expired or was idle too long. Sign in again to continue.");
    return;
  }
  document.querySelector("#session-warning").hidden = remaining > 2 * 60 * 1000;
  sessionTimer = window.setTimeout(checkSessionTime, Math.min(remaining, 15000));
}

function recordActivity(event) {
  if (!event.isTrusted || !state.token) return;
  checkSessionTime();
  if (!state.token) return;
  state.lastActivity = Date.now();
  sessionStorage.setItem("forenx.activity", String(state.lastActivity));
  checkSessionTime();
  if (Date.now() - activityRequestAt < 60000) return;
  activityRequestAt = Date.now();
  // Only real user interaction refreshes server activity; no background polling.
  void api("/api/v1/auth/me").then((user) => {
    state.user = user;
    if (user.must_change_password && requiredPasswordForm.hidden) showPasswordGate();
  }).catch(() => {});
}

function showWorkspace() {
  if (!state.token || !state.user) return;
  if (state.user.must_change_password) {
    showPasswordGate();
    return;
  }
  authView.hidden = true;
  workspace.hidden = false;
  const displayName = state.user?.display_name || "Authorized user";
  const initials = displayName
    .split(/\s+/)
    .slice(0, 2)
    .map((part) => part[0])
    .join("")
    .toUpperCase();
  document.querySelector("#user-name").textContent = displayName;
  document.querySelector("#user-role").textContent = (state.user?.role || "user").replaceAll("-", " ");
  document.querySelector("#user-avatar").textContent = initials || "FX";
  document.querySelector("#new-case-button").hidden = !can("case:create");
  document.querySelector("#user-admin-nav").hidden = !can("user:manage");
}

function formatDate(value) {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function formatBytes(value) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size >= 10 || unit === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`;
}

function formatTimecode(seconds) {
  const safeSeconds = Number.isFinite(seconds) && seconds >= 0 ? seconds : 0;
  const wholeMilliseconds = Math.round(safeSeconds * 1000);
  const hours = Math.floor(wholeMilliseconds / 3_600_000);
  const minutes = Math.floor((wholeMilliseconds % 3_600_000) / 60_000);
  const wholeSeconds = Math.floor((wholeMilliseconds % 60_000) / 1000);
  const milliseconds = wholeMilliseconds % 1000;
  return [hours, minutes, wholeSeconds]
    .map((value) => String(value).padStart(2, "0"))
    .join(":") + `.${String(milliseconds).padStart(3, "0")}`;
}

function appendCell(row, value) {
  const cell = document.createElement("td");
  cell.textContent = value;
  row.append(cell);
  return cell;
}

function appendTextElement(parent, tag, text, className) {
  const element = document.createElement(tag);
  element.textContent = text;
  if (className) element.className = className;
  parent.append(element);
  return element;
}

function filteredCases() {
  const query = document.querySelector("#case-search").value.trim().toLocaleLowerCase();
  if (!query) return state.cases;
  return state.cases.filter((item) =>
    [item.case_reference, item.agency, item.investigating_officer]
      .join(" ")
      .toLocaleLowerCase()
      .includes(query),
  );
}

function renderCases() {
  const cases = filteredCases();
  caseRows.replaceChildren();
  document.querySelector(".table-scroll").hidden = cases.length === 0;
  emptyCases.hidden = cases.length !== 0;
  document.querySelector("#queue-status").textContent =
    `${state.cases.length} protected ${state.cases.length === 1 ? "record" : "records"}`;

  const reviewStatuses = new Set(["examiner-review", "supervisor-review"]);
  document.querySelector("#metric-total").textContent = state.cases.length;
  document.querySelector("#metric-intake").textContent = state.cases.filter((item) =>
    ["intake", "acquisition"].includes(item.status),
  ).length;
  document.querySelector("#metric-review").textContent = state.cases.filter((item) =>
    reviewStatuses.has(item.status),
  ).length;
  document.querySelector("#metric-approved").textContent = state.cases.filter((item) =>
    ["approved", "closed"].includes(item.status),
  ).length;

  for (const item of cases) {
    const row = document.createElement("tr");
    row.tabIndex = 0;
    row.dataset.caseId = item.case_id;
    appendCell(row, item.case_reference);
    appendCell(row, item.agency);
    appendCell(row, item.investigating_officer);
    const statusCell = appendCell(row, "");
    appendTextElement(statusCell, "span", item.status.replaceAll("-", " "), "status-badge");
    appendCell(row, formatDate(item.updated_at));
    row.addEventListener("click", () => openCase(item.case_id));
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openCase(item.case_id);
      }
    });
    caseRows.append(row);
  }
}

async function loadCases() {
  try {
    state.cases = await api("/api/v1/cases");
    renderCases();
  } catch (error) {
    if (error.status === 401 || error.name === "AbortError") return;
    document.querySelector("#queue-status").textContent = "Protected records unavailable";
    showToast(error.message);
  }
}

function renderExhibits(exhibits) {
  const list = document.querySelector("#exhibit-list");
  list.replaceChildren();
  if (exhibits.length === 0) {
    appendTextElement(list, "div", "No exhibits have been registered for this case.", "inline-empty");
    return;
  }
  for (const exhibit of exhibits) {
    const item = document.createElement("article");
    item.className = "exhibit-item";
    const identity = document.createElement("div");
    appendTextElement(identity, "span", "Exhibit");
    appendTextElement(identity, "strong", exhibit.exhibit_number);
    const device = document.createElement("div");
    appendTextElement(device, "span", "Device");
    appendTextElement(
      device,
      "strong",
      [exhibit.manufacturer, exhibit.model, exhibit.device_type].filter(Boolean).join(" · "),
    );
    const collector = document.createElement("div");
    appendTextElement(collector, "span", "Collected by");
    appendTextElement(collector, "strong", `${exhibit.collector} · ${formatDate(exhibit.collected_at)}`);
    appendTextElement(item, "span", exhibit.seal_condition, "seal-state");
    item.prepend(identity, device, collector);
    list.append(item);
  }
}

function renderCaseTeam(users, assignments) {
  const section = document.querySelector("#case-team-section");
  section.hidden = !can("case:assign");
  if (section.hidden) return;

  const usersById = new Map(users.map((user) => [user.user_id, user]));
  const assignedIds = new Set(assignments.map((assignment) => assignment.user_id));
  const select = document.querySelector("#case-team-user");
  const grantButton = document.querySelector("#assign-case-user");
  select.replaceChildren();
  for (const user of users.filter((item) => item.active && !assignedIds.has(item.user_id))) {
    const option = document.createElement("option");
    option.value = user.user_id;
    option.textContent = `${user.display_name} · ${user.role.replaceAll("-", " ")}`;
    select.append(option);
  }
  grantButton.disabled = select.options.length === 0;

  const list = document.querySelector("#case-team-list");
  list.replaceChildren();
  for (const assignment of assignments) {
    const assignedUser = usersById.get(assignment.user_id);
    const item = document.createElement("article");
    item.className = "case-team-item";
    const identity = document.createElement("div");
    appendTextElement(identity, "strong", assignedUser?.display_name || assignment.user_id);
    appendTextElement(
      identity,
      "small",
      assignedUser?.role.replaceAll("-", " ") || "User record unavailable",
    );
    const provenance = document.createElement("div");
    appendTextElement(provenance, "span", "Access granted");
    appendTextElement(provenance, "small", formatDate(assignment.assigned_at));
    item.append(identity, provenance);

    if (state.user.role === "administrator" || assignment.user_id !== state.user.user_id) {
      const revoke = appendTextElement(
        item,
        "button",
        "Revoke",
        "button button-secondary",
      );
      revoke.type = "button";
      revoke.addEventListener("click", async () => {
        revoke.disabled = true;
        try {
          await api(
            `/api/v1/cases/${state.selectedCase.case_id}/assignments/${assignment.user_id}/revoke`,
            { method: "POST" },
          );
          caseDetailDialog.close();
          await openCase(state.selectedCase.case_id);
          showToast("Case access revoked and recorded in the audit chain.");
        } catch (error) {
          showToast(error.message);
          revoke.disabled = false;
        }
      });
    }
    list.append(item);
  }
}

function renderEvidence(records) {
  const list = document.querySelector("#evidence-list");
  list.replaceChildren();
  if (records.length === 0) {
    appendTextElement(
      list,
      "div",
      "No source files have been ingested for this case.",
      "inline-empty",
    );
    return;
  }
  for (const record of records) {
    const item = document.createElement("article");
    item.className = "evidence-item";
    const identity = document.createElement("div");
    appendTextElement(
      identity,
      "span",
      record.parent_source_id
        ? "recovered video derivative"
        : record.media_kind.replaceAll("-", " "),
    );
    appendTextElement(identity, "strong", record.original_filename);
    const integrity = document.createElement("div");
    appendTextElement(integrity, "span", `${formatBytes(record.byte_size)} · SHA-256`);
    appendTextElement(integrity, "code", record.sha256);
    item.append(identity, integrity);
    const actions = document.createElement("div");
    actions.className = "evidence-actions";
    if (record.media_kind === "raw-disk-image") {
      const recoveryButton = appendTextElement(
        actions,
        "button",
        "Open recovery",
        "button button-primary verify-button",
      );
      recoveryButton.type = "button";
      recoveryButton.addEventListener("click", () => openRecovery(record));
    }
    if (record.media_kind === "video-file") {
      const examineButton = appendTextElement(
        actions,
        "button",
        "Open examiner",
        "button button-primary verify-button",
      );
      examineButton.type = "button";
      examineButton.addEventListener("click", () => openVideoExaminer(record));
    }
    if (can("case:process")) {
      const verifyButton = appendTextElement(actions, "button", "Verify hash", "button button-secondary verify-button");
      verifyButton.type = "button";
      verifyButton.addEventListener("click", async () => {
        verifyButton.disabled = true;
        verifyButton.textContent = "Verifying…";
        try {
          const result = await api(`/api/v1/evidence/${record.source_id}/verify`, {
            method: "POST",
          });
          showToast(result.valid ? "Evidence integrity verified." : "Evidence integrity mismatch detected.");
          caseDetailDialog.close();
          await openCase(record.case_id);
        } catch (error) {
          showToast(error.message);
        } finally {
          verifyButton.disabled = false;
          verifyButton.textContent = "Verify hash";
        }
      });
    }
    item.append(actions);
    list.append(item);
  }
}

async function downloadRecoveryArtifact(artifact, button) {
  const generation = sessionGeneration;
  button.disabled = true;
  button.textContent = "Checking download…";
  try {
    const file = await request(
      `/api/v1/recovery-artifacts/${artifact.artifact_id}/download`,
      {}, "blob",
    );
    const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
    assertSession(generation);
    const observed = [...new Uint8Array(digest)]
      .map((value) => value.toString(16).padStart(2, "0"))
      .join("");
    if (observed !== artifact.sha256) {
      throw new Error("Downloaded artifact hash did not match its recovery record");
    }
    const link = document.createElement("a");
    link.href = URL.createObjectURL(file);
    link.download = artifact.filename;
    link.click();
    URL.revokeObjectURL(link.href);
    showToast("Recovered recording verified and downloaded.");
  } catch (error) {
    showToast(error.message);
  } finally {
    button.disabled = false;
    button.textContent = "Verify and download";
  }
}

async function extractRecoveryRecording(scan, recording, button) {
  button.disabled = true;
  button.textContent = "Extracting exact extents…";
  try {
    await api(
      `/api/v1/recovery-scans/${scan.scan_id}/recordings/${encodeURIComponent(recording.recording_id)}/extract`,
      { method: "POST" },
    );
    await refreshRecoveryScans();
    showToast("Recording extracted, hashed, and stored read-only.");
  } catch (error) {
    showToast(error.message);
    button.disabled = false;
    button.textContent = "Extract recording";
  }
}

async function registerRecoveryArtifact(artifact, button) {
  button.disabled = true;
  button.textContent = "Verifying and registering…";
  try {
    await api(`/api/v1/recovery-artifacts/${artifact.artifact_id}/register-evidence`, {
      method: "POST",
    });
    state.selectedEvidenceSources = await api(
      `/api/v1/cases/${artifact.case_id}/evidence`,
    );
    await refreshRecoveryScans();
    showToast("Recovered stream registered in the protected video examiner.");
  } catch (error) {
    showToast(error.message);
    button.disabled = false;
    button.textContent = "Register for examination";
  }
}

async function openRegisteredRecoverySource(artifact) {
  try {
    const sources = await api(`/api/v1/cases/${artifact.case_id}/evidence`);
    state.selectedEvidenceSources = sources;
    const source = sources.find(
      (item) => item.source_id === artifact.examination_source_id,
    );
    if (!source) throw new Error("Registered examination source is unavailable");
    recoveryDialog.close();
    await openVideoExaminer(source);
  } catch (error) {
    showToast(error.message);
  }
}

function renderRecoveryScans() {
  const list = document.querySelector("#recovery-scan-list");
  const readiness = document.querySelector("#recovery-readiness");
  list.replaceChildren();
  if (state.currentRecoveryScans.length === 0) {
    readiness.textContent =
      "No recovery scan exists for this image. Run a probe to identify observable vendor structures.";
    return;
  }
  readiness.textContent =
    `${state.currentRecoveryScans.length} immutable recovery ${state.currentRecoveryScans.length === 1 ? "scan" : "scans"}. Support remains experimental unless the recorder model has passed the validation register.`;
  for (const scan of [...state.currentRecoveryScans].reverse()) {
    const card = document.createElement("article");
    card.className = "recovery-scan-card";
    const header = document.createElement("header");
    const identity = document.createElement("div");
    appendTextElement(identity, "span", `Scan ${scan.scan_id.slice(0, 8)}`);
    appendTextElement(identity, "h3", `${scan.vendor} · ${scan.filesystem}`);
    appendTextElement(
      identity,
      "small",
      `${scan.adapter_id} v${scan.adapter_version} · ${formatDate(scan.created_at)}`,
    );
    appendTextElement(
      header,
      "span",
      `${Math.round(scan.confidence * 100)}% probe confidence`,
      "maturity",
    );
    header.prepend(identity);
    card.append(header);

    const provenance = document.createElement("div");
    provenance.className = "recovery-provenance";
    appendTextElement(
      provenance,
      "code",
      `Source SHA-256 ${scan.source_sha256}`,
    );
    for (const evidence of scan.probe_evidence) {
      appendTextElement(
        provenance,
        "small",
        `${evidence.description} at byte offset ${evidence.offset}`,
      );
    }
    for (const warning of scan.warnings) {
      appendTextElement(provenance, "small", `Warning: ${warning}`);
    }
    card.append(provenance);

    const recordings = document.createElement("div");
    recordings.className = "recovery-recording-list";
    const artifacts = state.recoveryArtifactsByScan.get(scan.scan_id) || [];
    if (scan.recordings.length === 0) {
      appendTextElement(
        recordings,
        "div",
        "No bounded recording descriptors were enumerated.",
        "inline-empty",
      );
    }
    for (const recording of scan.recordings) {
      const item = document.createElement("article");
      item.className = "recovery-recording-item";
      const details = document.createElement("div");
      appendTextElement(
        details,
        "strong",
        `Channel ${recording.channel || "unknown"} · ${recording.state.replaceAll("-", " ")}`,
      );
      appendTextElement(
        details,
        "small",
        recording.start_time && recording.end_time
          ? `${formatDate(recording.start_time)} → ${formatDate(recording.end_time)}`
          : "Recorder timestamps are incomplete or uncertain",
      );
      appendTextElement(
        details,
        "code",
        recording.extents
          .map((extent) => `offset ${extent.offset}, ${formatBytes(extent.length)}`)
          .join(" · "),
      );
      const existing = artifacts.find(
        (artifact) => artifact.recording_id === recording.recording_id,
      );
      const actions = document.createElement("div");
      actions.className = "recovery-recording-actions";
      if (existing) {
        const download = appendTextElement(
          actions,
          "button",
          "Verify and download",
          "button button-secondary",
        );
        download.type = "button";
        download.addEventListener("click", () =>
          downloadRecoveryArtifact(existing, download),
        );
        const examination = appendTextElement(
          actions,
          "button",
          existing.examination_source_id
            ? "Open examiner"
            : "Register for examination",
          "button button-primary",
        );
        examination.type = "button";
        examination.disabled =
          !existing.examination_source_id &&
          (!can("case:process") || state.selectedCase?.status === "closed");
        examination.addEventListener("click", () =>
          existing.examination_source_id
            ? openRegisteredRecoverySource(existing)
            : registerRecoveryArtifact(existing, examination),
        );
        appendTextElement(
          details,
          "small",
          `Extracted ${formatBytes(existing.byte_size)} · SHA-256 ${existing.sha256}`,
          "recovered-artifact-detail",
        );
      } else {
        const extract = appendTextElement(
          actions,
          "button",
          "Extract recording",
          "button button-primary",
        );
        extract.type = "button";
        extract.disabled = !can("case:process") || state.selectedCase?.status === "closed";
        extract.addEventListener("click", () =>
          extractRecoveryRecording(scan, recording, extract),
        );
      }
      item.append(details, actions);
      recordings.append(item);
    }
    card.append(recordings);
    list.append(card);
  }
}

async function refreshRecoveryScans() {
  const scans = await api(
    `/api/v1/evidence/${state.selectedRecoverySource.source_id}/recovery-scans`,
  );
  const artifactGroups = await Promise.all(
    scans.map((scan) =>
      api(`/api/v1/recovery-scans/${scan.scan_id}/artifacts`).then((artifacts) => [
        scan.scan_id,
        artifacts,
      ]),
    ),
  );
  state.currentRecoveryScans = scans;
  state.recoveryArtifactsByScan = new Map(artifactGroups);
  renderRecoveryScans();
}

async function openRecovery(record) {
  state.selectedRecoverySource = record;
  state.currentRecoveryScans = [];
  state.recoveryArtifactsByScan = new Map();
  document.querySelector("#recovery-filename").textContent = record.original_filename;
  document.querySelector("#recovery-hash").textContent = `SHA-256 ${record.sha256}`;
  const startButton = document.querySelector("#start-recovery-scan");
  startButton.hidden = !can("case:process") || state.selectedCase?.status === "closed";
  caseDetailDialog.close();
  recoveryDialog.showModal();
  try {
    await refreshRecoveryScans();
  } catch (error) {
    showToast(error.message);
  }
}

function renderBiometricAuthorizations(authorizations, caseRecord, evidenceSources) {
  const list = document.querySelector("#biometric-authorization-list");
  const readiness = document.querySelector("#biometric-readiness");
  const createButton = document.querySelector("#authorize-biometric-button");
  const videoSources = evidenceSources.filter(
    (record) => record.media_kind === "video-file",
  );
  createButton.hidden =
    !can("biometric:authorize") ||
    caseRecord.status === "closed" ||
    videoSources.length === 0;
  readiness.textContent = videoSources.length === 0
    ? "Ingest and inspect a video source before requesting controlled face analysis."
    : caseRecord.status === "closed"
      ? "This case is closed. New biometric-analysis authorization is blocked."
      : "Analysis remains disabled until a supervisor records a lawful purpose, single-reference provenance, retention deadline, and threshold policy.";
  list.replaceChildren();
  if (authorizations.length === 0) {
    appendTextElement(
      list,
      "div",
      "No biometric-analysis authorization has been recorded.",
      "inline-empty",
    );
    return;
  }
  for (const authorization of authorizations) {
    const active = new Date(authorization.retention_until).getTime() > Date.now();
    const item = document.createElement("article");
    item.className = "biometric-authorization-item";
    const identity = document.createElement("div");
    appendTextElement(
      identity,
      "span",
      authorization.mode === "one-to-one" ? "One-to-one only" : authorization.mode,
    );
    appendTextElement(identity, "strong", authorization.source_filename);
    appendTextElement(identity, "small", authorization.purpose);
    const governance = document.createElement("div");
    appendTextElement(governance, "span", "Authority and expiry");
    appendTextElement(governance, "strong", authorization.legal_authority_reference);
    appendTextElement(
      governance,
      "small",
      `Retention until ${formatDate(authorization.retention_until)}`,
    );
    const status = appendTextElement(
      item,
      "span",
      active ? "Active" : "Expired",
      "status-badge",
    );
    if (!active) status.classList.add("invalid");
    item.prepend(identity, governance);
    list.append(item);
  }
}

async function downloadReportPackage(report, button) {
  const generation = sessionGeneration;
  button.disabled = true;
  button.textContent = "Checking download…";
  try {
    const archive = await request(`/api/v1/reports/${report.package_id}/download`, {}, "blob");
    const digest = await crypto.subtle.digest("SHA-256", await archive.arrayBuffer());
    assertSession(generation);
    const observed = [...new Uint8Array(digest)]
      .map((value) => value.toString(16).padStart(2, "0"))
      .join("");
    if (observed !== report.archive_sha256) {
      throw new Error("Downloaded package hash does not match the protected export record");
    }
    const link = document.createElement("a");
    const objectUrl = URL.createObjectURL(archive);
    link.href = objectUrl;
    link.download = `forenx-${report.package_id}.zip`;
    link.click();
    URL.revokeObjectURL(objectUrl);
    showToast("Signed package downloaded and its SHA-256 verified.");
  } catch (error) {
    showToast(error.message);
  } finally {
    button.disabled = false;
    button.textContent = "Download verified package";
  }
}

function renderReports(reports, caseRecord, evidenceSources) {
  const list = document.querySelector("#report-list");
  const readiness = document.querySelector("#report-readiness");
  const createButton = document.querySelector("#create-report-button");
  const approved = ["approved", "closed"].includes(caseRecord.status);
  const hasVideo = evidenceSources.some((record) => record.media_kind === "video-file");
  createButton.hidden = !can("case:approve") || !approved || !hasVideo;
  readiness.textContent = !approved
    ? "Report signing unlocks after supervisor approval. Draft observations remain editable only by adding new immutable events."
    : !hasVideo
      ? "Ingest and inspect a video evidence source before creating an examination report."
      : "Every package contains a PDF, structured JSON, signed manifest, and independent verification data.";
  list.replaceChildren();
  if (reports.length === 0) {
    appendTextElement(list, "div", "No signed report packages have been created.", "inline-empty");
    return;
  }
  for (const report of reports) {
    const item = document.createElement("article");
    item.className = "report-item";
    const identity = document.createElement("div");
    appendTextElement(identity, "span", "Signed examination package");
    appendTextElement(identity, "strong", report.report_title);
    appendTextElement(identity, "small", formatDate(report.created_at));
    const integrity = document.createElement("div");
    appendTextElement(integrity, "span", "Signing-key fingerprint");
    appendTextElement(integrity, "code", report.public_key_fingerprint);
    appendTextElement(integrity, "small", `Archive SHA-256 ${report.archive_sha256.slice(0, 20)}…`);
    const download = appendTextElement(
      item,
      "button",
      "Download verified package",
      "button button-primary",
    );
    download.type = "button";
    download.addEventListener("click", () => downloadReportPackage(report, download));
    item.prepend(identity, integrity);
    list.append(item);
  }
}

function primaryVideoStream(inspection) {
  return inspection.result.streams.find((stream) => stream.type === "video") || null;
}

function renderInspection(inspection) {
  const result = inspection.result;
  const video = primaryVideoStream(inspection);
  document.querySelector("#inspection-tool").textContent =
    `${result.library} ${result.library_version} · ${formatDate(inspection.inspected_at)}`;
  document.querySelector("#media-container").textContent = result.format_long_name;
  document.querySelector("#media-duration").textContent =
    result.duration_seconds === null ? "Not declared" : formatTimecode(result.duration_seconds);
  document.querySelector("#media-codec").textContent = video?.codec_long_name || video?.codec_name || "No video stream";
  document.querySelector("#media-resolution").textContent =
    video?.width && video?.height ? `${video.width} × ${video.height}` : "Not declared";
  document.querySelector("#media-frame-rate").textContent = video?.average_frame_rate
    ? `${video.average_frame_rate.toFixed(3)} fps`
    : "Not declared";
  document.querySelector("#media-bit-rate").textContent = result.bit_rate
    ? `${(result.bit_rate / 1000).toFixed(0)} kb/s`
    : "Not declared";
}

function renderBookmarks(bookmarks) {
  const list = document.querySelector("#bookmark-list");
  list.replaceChildren();
  document.querySelector("#bookmark-count").textContent =
    `${bookmarks.length} ${bookmarks.length === 1 ? "bookmark" : "bookmarks"}`;
  if (bookmarks.length === 0) {
    appendTextElement(
      list,
      "li",
      "No examiner observations have been bookmarked in this video.",
      "inline-empty",
    );
    return;
  }
  for (const bookmark of bookmarks) {
    const item = document.createElement("li");
    item.className = "bookmark-item";
    const seek = appendTextElement(
      item,
      "button",
      formatTimecode(bookmark.timestamp_ms / 1000),
    );
    seek.type = "button";
    seek.addEventListener("click", () => {
      evidencePlayer.currentTime = bookmark.timestamp_ms / 1000;
      evidencePlayer.focus();
    });
    const copy = document.createElement("div");
    appendTextElement(copy, "strong", bookmark.title);
    if (bookmark.note) appendTextElement(copy, "small", bookmark.note);
    item.append(copy);
    appendTextElement(item, "span", formatDate(bookmark.created_at));
    list.append(item);
  }
}

function activeAuthorization(authorizations) {
  const now = Date.now();
  return authorizations.find(
    (authorization) => new Date(authorization.retention_until).getTime() > now,
  ) || null;
}

function openFaceDetection(run) {
  document.querySelector("#face-detection-title").textContent =
    `${run.faces.length} ${run.faces.length === 1 ? "face" : "faces"} detected`;
  document.querySelector("#face-detection-subtitle").textContent =
    `${state.selectedEvidence.original_filename} · ${formatTimecode(run.observed_timestamp_ms / 1000)}`;
  document.querySelector("#detection-observed-time").textContent =
    formatTimecode(run.observed_timestamp_ms / 1000);
  document.querySelector("#detection-frame-hash").textContent = run.source_frame_sha256;
  document.querySelector("#detection-model").textContent =
    `${run.model_name} ${run.model_version} · ${run.runtime} ${run.runtime_version}`;
  document.querySelector("#detection-model-hash").textContent = run.model_sha256;
  document.querySelector("#detection-threshold").textContent =
    `score ≥ ${run.score_threshold.toFixed(2)} · NMS ${run.nms_threshold.toFixed(2)}`;
  document.querySelector("#detection-authorization").textContent = run.authorization_id;
  const image = document.querySelector("#face-detection-image");
  image.src =
    `/api/v1/evidence/${run.source_id}/face-detections/${run.run_id}/preview`;
  const overlay = document.querySelector("#face-detection-overlay");
  overlay.replaceChildren();
  overlay.setAttribute("viewBox", `0 0 ${run.frame_width} ${run.frame_height}`);
  for (const face of run.faces) {
    const box = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    box.setAttribute("x", face.x);
    box.setAttribute("y", face.y);
    box.setAttribute("width", face.width);
    box.setAttribute("height", face.height);
    box.setAttribute("vector-effect", "non-scaling-stroke");
    overlay.append(box);
    for (const landmark of face.landmarks) {
      const point = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      point.setAttribute("cx", landmark.x);
      point.setAttribute("cy", landmark.y);
      point.setAttribute("r", Math.max(1.5, Math.min(run.frame_width, run.frame_height) / 180));
      point.setAttribute("vector-effect", "non-scaling-stroke");
      overlay.append(point);
    }
  }
  faceDetectionDialog.showModal();
}

function renderFaceDetections(runs, authorizations) {
  const list = document.querySelector("#face-detection-list");
  const readiness = document.querySelector("#face-detection-readiness");
  const detectButton = document.querySelector("#detect-current-frame");
  const authorization = activeAuthorization(authorizations);
  detectButton.hidden = !can("case:process");
  detectButton.disabled = !authorization;
  readiness.textContent = authorization
    ? `Authorized for one-to-one case analysis until ${formatDate(authorization.retention_until)}. Detection does not identify a person.`
    : "Face processing is locked until a supervisor records an active case-specific authorization.";
  list.replaceChildren();
  if (runs.length === 0) {
    appendTextElement(
      list,
      "div",
      "No source frames have been processed for faces.",
      "inline-empty",
    );
    return;
  }
  for (const run of runs) {
    const item = document.createElement("article");
    item.className = "face-detection-item";
    const identity = document.createElement("div");
    appendTextElement(identity, "span", formatTimecode(run.observed_timestamp_ms / 1000));
    appendTextElement(
      identity,
      "strong",
      `${run.faces.length} ${run.faces.length === 1 ? "face" : "faces"} detected`,
    );
    appendTextElement(
      identity,
      "small",
      `${run.model_name} ${run.model_version} · score threshold ${run.score_threshold.toFixed(2)}`,
    );
    const view = appendTextElement(
      item,
      "button",
      "Review source-linked frame",
      "button button-secondary",
    );
    view.type = "button";
    view.addEventListener("click", () => openFaceDetection(run));
    item.prepend(identity);
    list.append(item);
  }
}

function renderFaceTracking(runs, authorizations, detections) {
  const list = document.querySelector("#face-tracking-list");
  const readiness = document.querySelector("#face-tracking-readiness");
  const createButton = document.querySelector("#create-face-tracks");
  const authorized = activeAuthorization(authorizations);
  const distinctFrames = new Set(
    detections.map((run) => `${run.observed_timestamp_ms}:${run.source_frame_sha256}`),
  ).size;
  createButton.hidden = !can("case:process");
  createButton.disabled = !authorized || distinctFrames < 2;
  readiness.textContent = !authorized
    ? "Tracking is locked until an active face-analysis authorization exists."
    : distinctFrames < 2
      ? "Detect faces at two or more distinct video positions before building a track."
      : "Tracks use bounding-box overlap only. They are continuity hypotheses, never identity recognition.";
  document.querySelector("#track-start-time").textContent = formatTimecode(
    state.trackStartTimestampMs / 1000,
  );
  document.querySelector("#track-end-time").textContent = formatTimecode(
    state.trackEndTimestampMs / 1000,
  );
  list.replaceChildren();
  for (const run of runs) {
    const observationCount = run.tracks.reduce(
      (total, track) => total + track.observations.length,
      0,
    );
    const item = document.createElement("article");
    item.className = "face-tracking-item";
    const identity = document.createElement("div");
    appendTextElement(
      identity,
      "strong",
      `${run.tracks.length} geometric ${run.tracks.length === 1 ? "track" : "tracks"}`,
    );
    appendTextElement(
      identity,
      "small",
      `${run.distinct_frame_count} frames · ${observationCount} observations`,
    );
    const range = document.createElement("div");
    appendTextElement(range, "span", "Selected range");
    appendTextElement(
      range,
      "small",
      `${formatTimecode(run.start_timestamp_ms / 1000)} – ${formatTimecode(run.end_timestamp_ms / 1000)}`,
    );
    appendTextElement(
      range,
      "small",
      `${run.algorithm} ${run.algorithm_version} · IoU ≥ ${run.iou_threshold.toFixed(2)}`,
    );
    item.append(identity, range);
    list.append(item);
  }
}

async function openVideoExaminer(record) {
  caseDetailDialog.close();
  document.querySelector("#player-error").hidden = true;
  try {
    let inspection;
    try {
      inspection = await api(`/api/v1/evidence/${record.source_id}/inspection`);
    } catch (error) {
      if (error.status !== 404 || !can("case:process")) throw error;
      showToast("Inspecting the video in the protected local worker…");
      inspection = await api(`/api/v1/evidence/${record.source_id}/inspect`, {
        method: "POST",
      });
    }
    const [bookmarks, authorizations, faceDetections, faceTrackingRuns] = await Promise.all([
      api(`/api/v1/evidence/${record.source_id}/bookmarks`),
      api(`/api/v1/evidence/${record.source_id}/biometric-authorizations`),
      api(`/api/v1/evidence/${record.source_id}/face-detections`),
      api(`/api/v1/evidence/${record.source_id}/face-tracks`),
    ]);
    state.selectedEvidence = record;
    state.currentInspection = inspection;
    state.currentFaceDetections = faceDetections;
    state.currentFaceTrackingRuns = faceTrackingRuns;
    state.currentBiometricAuthorizations = authorizations;
    state.trackStartTimestampMs = faceDetections.length
      ? Math.min(...faceDetections.map((run) => run.observed_timestamp_ms))
      : 0;
    state.trackEndTimestampMs = faceDetections.length
      ? Math.max(...faceDetections.map((run) => run.observed_timestamp_ms))
      : 0;
    document.querySelector("#video-title").textContent = record.original_filename;
    document.querySelector("#video-hash").textContent = `SHA-256 ${record.sha256}`;
    document.querySelector("#bookmark-current").hidden = !can("case:process");
    renderInspection(inspection);
    renderBookmarks(bookmarks);
    renderFaceDetections(faceDetections, authorizations);
    renderFaceTracking(faceTrackingRuns, authorizations, faceDetections);
    evidencePlayer.src = `/api/v1/evidence/${record.source_id}/content`;
    videoDialog.showModal();
  } catch (error) {
    showToast(error.message);
  }
}

function renderActivity(events, verification) {
  const list = document.querySelector("#activity-list");
  const chip = document.querySelector("#activity-verification");
  list.replaceChildren();
  chip.classList.toggle("valid", verification.valid);
  chip.classList.toggle("invalid", !verification.valid);
  chip.textContent = verification.valid
    ? `✓ ${verification.checked_events} events verified`
    : `Integrity warning at event ${verification.failure_sequence || "unknown"}`;
  for (const event of events) {
    const item = document.createElement("li");
    item.className = "activity-item";
    appendTextElement(item, "time", formatDate(event.occurred_at));
    const details = document.createElement("div");
    appendTextElement(details, "strong", actionLabels[event.action] || event.action.replaceAll("_", " "));
    appendTextElement(details, "code", `SHA-256 ${event.event_hash.slice(0, 20)}…`);
    item.append(details);
    list.append(item);
  }
}

function renderTransition(caseRecord) {
  const section = document.querySelector("#transition-section");
  const select = document.querySelector("#transition-target");
  const allowed = (caseTransitions[caseRecord.status] || []).filter((target) =>
    ["approved", "closed"].includes(target) ? can("case:approve") : can("case:process"),
  );
  section.hidden = allowed.length === 0;
  select.replaceChildren();
  for (const target of allowed) {
    const option = document.createElement("option");
    option.value = target;
    option.textContent = target.replaceAll("-", " ");
    select.append(option);
  }
}

async function openCase(caseId) {
  try {
    const [caseRecord, exhibits, evidence, events, verification, reports] = await Promise.all([
      api(`/api/v1/cases/${caseId}`),
      api(`/api/v1/cases/${caseId}/exhibits`),
      api(`/api/v1/cases/${caseId}/evidence`),
      api(`/api/v1/cases/${caseId}/activity`),
      api(`/api/v1/cases/${caseId}/activity/verify`),
      api(`/api/v1/cases/${caseId}/reports`),
    ]);
    const authorizationGroups = await Promise.all(
      evidence
        .filter((source) => source.media_kind === "video-file")
        .map(async (source) => {
          const authorizations = await api(
            `/api/v1/evidence/${source.source_id}/biometric-authorizations`,
          );
          return authorizations.map((authorization) => ({
            ...authorization,
            source_filename: source.original_filename,
          }));
        }),
    );
    const biometricAuthorizations = authorizationGroups.flat();
    let caseUsers = [];
    let caseAssignments = [];
    if (can("case:assign")) {
      [caseUsers, caseAssignments] = await Promise.all([
        api("/api/v1/users"),
        api(`/api/v1/cases/${caseId}/assignments`),
      ]);
    }
    state.selectedCase = caseRecord;
    state.selectedExhibits = exhibits;
    state.selectedEvidenceSources = evidence;
    state.biometricAuthorizations = biometricAuthorizations;
    state.caseUsers = caseUsers;
    state.caseAssignments = caseAssignments;
    document.querySelector("#detail-reference").textContent = caseRecord.case_reference;
    document.querySelector("#detail-agency").textContent = caseRecord.agency;
    document.querySelector("#detail-status").textContent = caseRecord.status.replaceAll("-", " ");
    document.querySelector("#detail-officer").textContent = caseRecord.investigating_officer;
    document.querySelector("#detail-station").textContent = caseRecord.police_station || "Not supplied";
    document.querySelector("#detail-classification").textContent = caseRecord.classification;
    document.querySelector("#detail-updated").textContent = formatDate(caseRecord.updated_at);
    document.querySelector("#add-exhibit-button").hidden = !can("exhibit:create");
    document.querySelector("#ingest-evidence-button").hidden = !can("evidence:ingest");
    renderCaseTeam(caseUsers, caseAssignments);
    renderExhibits(exhibits);
    renderEvidence(evidence);
    renderBiometricAuthorizations(biometricAuthorizations, caseRecord, evidence);
    renderReports(reports, caseRecord, evidence);
    renderActivity(events, verification);
    renderTransition(caseRecord);
    caseDetailDialog.showModal();
  } catch (error) {
    showToast(error.message);
  }
}

async function loadVendors() {
  try {
    const data = await api("/api/v1/vendors");
    const list = document.querySelector("#vendor-list");
    list.replaceChildren();
    for (const vendor of data.vendors) {
      const card = document.createElement("article");
      card.className = "vendor-card";
      const copy = document.createElement("div");
      appendTextElement(copy, "h3", vendor.display_name || vendor.adapter_id);
      appendTextElement(
        copy,
        "p",
        vendor.validated_models.length
          ? `Validated models: ${vendor.validated_models.join(", ")}`
          : "No recorder model has completed the real-device validation gate yet.",
      );
      const capabilities = document.createElement("div");
      capabilities.className = "capability-list";
      for (const capability of vendor.capabilities) {
        appendTextElement(capabilities, "span", capability.replaceAll("-", " "));
      }
      copy.append(capabilities);
      appendTextElement(card, "span", vendor.maturity, "maturity");
      card.prepend(copy);
      list.append(card);
    }
    vendorDialog.showModal();
  } catch (error) {
    showToast(error.message);
  }
}

function renderUsers(users) {
  const list = document.querySelector("#user-admin-list");
  list.replaceChildren();
  document.querySelector("#user-count").textContent =
    `${users.length} ${users.length === 1 ? "account" : "accounts"}`;
  for (const user of users) {
    authUserNames.set(user.user_id, `${user.display_name} (@${user.username})`);
    const item = document.createElement("article");
    item.className = "user-admin-item";
    const identity = document.createElement("div");
    appendTextElement(identity, "strong", user.display_name);
    appendTextElement(identity, "code", `@${user.username}`);
    const access = document.createElement("div");
    appendTextElement(access, "span", "Role");
    appendTextElement(access, "strong", user.role.replaceAll("-", " "));
    appendTextElement(access, "small", `Created ${formatDate(user.created_at)}`);
    if (user.must_change_password) appendTextElement(access, "small", "Password change required at sign-in");
    const status = appendTextElement(
      item,
      "span",
      user.active ? "Active" : "Inactive",
      "status-badge",
    );
    if (!user.active) status.classList.add("invalid");
    item.prepend(identity, access);
    if (user.user_id !== state.user?.user_id) {
      const actions = document.createElement("div");
      actions.className = "user-admin-actions";
      for (const [action, label] of [
        [user.active ? "suspend" : "activate", user.active ? "Suspend account" : "Activate account"],
        ["reset-password", "Reset password"],
        ["revoke-sessions", "Revoke sessions"],
      ]) {
        const button = appendTextElement(actions, "button", label, "button button-secondary");
        button.type = "button";
        button.addEventListener("click", () => openUserAction(user, action, label));
      }
      item.append(actions);
    } else appendTextElement(item, "small", "Your account · use My account to change your password", "user-admin-actions");
    list.append(item);
  }
}

async function loadUsers() {
  try {
    const users = await api("/api/v1/users");
    renderUsers(users);
    userAdminDialog.showModal();
    await loadAuthHistory(true);
  } catch (error) {
    showToast(error.message);
  }
}

function openUserAction(user, action, label) {
  userActionForm.reset();
  selectedUserAction = { user, action, label };
  document.querySelector("#user-action-title").textContent = label;
  document.querySelector("#user-action-submit").textContent = label;
  document.querySelector("#user-action-identity").textContent = `${user.display_name} (@${user.username})`;
  document.querySelector("#user-action-error").textContent = "";
  const temporaryField = document.querySelector("#temporary-password-field");
  temporaryField.hidden = action !== "reset-password";
  userActionForm.elements.new_password.required = action === "reset-password";
  userActionForm.elements.new_password.disabled = action !== "reset-password";
  const guidance = {
    suspend: "Immediately disable this account and revoke its sessions. Existing case records and audit history remain preserved.",
    activate: "Restore sign-in for this account. Previously revoked sessions remain invalid.",
    "reset-password": "Verify the person's identity before resetting. Issue a temporary password of at least 12 characters through an approved channel. All sessions will be revoked, and the user must choose a new password at sign-in.",
    "revoke-sessions": "Sign this user out on every device. The account remains active and may sign in again using its current password.",
  };
  document.querySelector("#user-action-guidance").textContent = guidance[action];
  userActionDialog.showModal();
}

const authActionLabels = {
  ADMINISTRATOR_BOOTSTRAPPED: "First administrator established",
  USER_CREATED: "Account created",
  LOGIN_SUCCEEDED: "Successful sign-in",
  LOGIN_FAILED: "Failed sign-in",
  AUTHENTICATION_THROTTLED: "Authentication attempt limited",
  REAUTHENTICATION_FAILED: "Password confirmation failed",
  SESSION_REVOKED: "Session signed out",
  ALL_SESSIONS_REVOKED: "All own sessions revoked",
  USER_SESSIONS_REVOKED: "User sessions revoked by administrator",
  PASSWORD_CHANGED: "Password changed",
  PASSWORD_RESET: "Temporary password issued",
  USER_ACTIVATED: "Account activated",
  USER_SUSPENDED: "Account suspended",
  ADMINISTRATOR_RECOVERED: "Administrator recovered by workstation operator",
};

async function loadAuthHistory(reset = false) {
  if (authHistoryBusy || !can("user:manage")) return;
  if (reset) authHistoryCursors = [null];
  authHistoryBusy = true;
  const errorLabel = document.querySelector("#auth-history-error");
  const refresh = document.querySelector("#auth-history-refresh");
  refresh.disabled = true;
  errorLabel.textContent = "";
  document.querySelector("#auth-history-newer").disabled = true;
  document.querySelector("#auth-history-older").disabled = true;
  try {
    const before = authHistoryCursors[authHistoryCursors.length - 1];
    const [events, integrity] = await Promise.all([
      api(`/api/v1/auth/events?limit=100${before === null ? "" : `&before=${before}`}`),
      api("/api/v1/auth/events/verify"),
    ]);
    const status = document.querySelector("#auth-history-integrity");
    status.textContent = integrity.valid
      ? `Stored chain verified · ${integrity.checked_events} events checked. This check does not authenticate events against an external anchor.`
      : "Integrity check failed. Authentication history may be incomplete or modified; preserve the data and investigate.";
    status.classList.toggle("integrity-failed", !integrity.valid);
    const list = document.querySelector("#auth-history-list");
    list.replaceChildren();
    if (events.length === 0) appendTextElement(list, "li", "No authentication events on this page.", "inline-empty");
    for (const entry of events) {
      const item = document.createElement("li");
      item.className = "auth-history-item";
      const heading = document.createElement("div");
      appendTextElement(heading, "strong", authActionLabels[entry.action] || entry.action.replaceAll("_", " "));
      appendTextElement(heading, "time", formatDate(entry.occurred_at));
      item.append(heading);
      appendTextElement(item, "small", `#${entry.sequence} · Actor: ${authUserNames.get(entry.actor_id) || entry.actor_id || "Unauthenticated"} · Subject: ${authUserNames.get(entry.subject) || entry.subject || "—"}`);
      // Render a deliberate subset; never dump an arbitrary auth payload into the page.
      if (entry.details?.reason) appendTextElement(item, "p", `Reason: ${entry.details.reason}`);
      list.append(item);
    }
    authHistoryNext = events.length === 100 ? Math.min(...events.map((entry) => entry.sequence)) : null;
  } catch (error) {
    if (error.name !== "AbortError") errorLabel.textContent = error.message;
  } finally {
    authHistoryBusy = false;
    refresh.disabled = false;
    document.querySelector("#auth-history-newer").disabled = authHistoryCursors.length <= 1;
    document.querySelector("#auth-history-older").disabled = authHistoryNext === null;
  }
}

const capabilityContent = {
  recovery: {
    eyebrow: "RECOVERY ENGINE",
    title: "Forensic recovery",
    copy: "The engine preserves source media and labels every recovered result by confidence and provenance.",
    checks: [
      ["Read-only evidence access", "Source bytes are read with bounded, offset-aware operations."],
      ["Hikvision metadata parsing", "Active recording metadata is parsed without mounting or altering the source."],
      ["Validated stream extraction", "H.264 and H.265 outputs are structurally checked before acceptance."],
      ["Device validation pending", "Real-model support remains experimental until laboratory images are supplied."],
    ],
  },
  exports: {
    eyebrow: "PORTABLE EVIDENCE",
    title: "Signed evidence packages",
    copy: "Every export is designed for independent verification outside the ForenX application.",
    checks: [
      ["SHA-256 inventory", "Source, recovered artifact, and custody data are hashed into one canonical manifest."],
      ["Ed25519 signature", "A laboratory key signs the manifest; only the public key is needed to verify it."],
      ["Trust fingerprint", "The signing identity is shown as a stable fingerprint for examiner comparison."],
    ],
  },
  audit: {
    eyebrow: "ASSURANCE",
    title: "Audit verification",
    copy: "ForenX continuously checks that case activity remains complete, ordered, and unmodified.",
    checks: [
      ["Append-only events", "Stored case activity cannot be edited or deleted by normal application operations."],
      ["Linked hashes", "Each event commits to the hash of the event before it."],
      ["Independent package verifier", "Evidence packages can be checked with the separate ForenX verifier."],
    ],
  },
};

function openCapability(name) {
  const content = capabilityContent[name];
  document.querySelector("#capability-eyebrow").textContent = content.eyebrow;
  document.querySelector("#capability-title").textContent = content.title;
  document.querySelector("#capability-copy").textContent = content.copy;
  const body = document.querySelector("#capability-body");
  body.replaceChildren();
  for (const [title, detail] of content.checks) {
    const check = document.createElement("div");
    check.className = "capability-check";
    appendTextElement(check, "span", "◇");
    const copy = document.createElement("div");
    appendTextElement(copy, "strong", title);
    appendTextElement(copy, "small", detail);
    check.append(copy);
    body.append(check);
  }
  capabilityDialog.showModal();
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (pendingLogout || !loginForm.reportValidity()) return;
  const errorLabel = document.querySelector("#login-error");
  errorLabel.textContent = "";
  setBusy(loginForm, true);
  try {
    const session = await api("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify(formPayload(loginForm)),
    });
    invalidateRequests();
    state.token = session.token;
    state.expiresAt = Date.parse(session.expires_at);
    state.idleTimeoutMs = (session.idle_timeout_seconds || 1800) * 1000;
    state.lastActivity = Date.now();
    state.browserSession = crypto.randomUUID();
    sessionStorage.setItem("forenx.session", state.token);
    sessionStorage.setItem("forenx.expires", String(state.expiresAt));
    sessionStorage.setItem("forenx.activity", String(state.lastActivity));
    sessionStorage.setItem("forenx.browser-session", state.browserSession);
    broadcastSessionChange(state.browserSession);
    state.user = await api("/api/v1/auth/me");
    activityRequestAt = Date.now();
    loginForm.reset();
    setAuthStatus("");
    checkSessionTime();
    showWorkspace();
    if (!state.user.must_change_password) await loadCases();
  } catch (error) {
    errorLabel.textContent = error.message;
  } finally {
    loginForm.elements.password.value = "";
    setBusy(loginForm, false);
  }
});

setupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!setupForm.reportValidity()) return;
  const errorLabel = document.querySelector("#setup-error");
  errorLabel.textContent = "";
  setBusy(setupForm, true);
  try {
    const payload = formPayload(setupForm);
    await api("/api/v1/setup", { method: "POST", body: JSON.stringify(payload) });
    setupForm.reset();
    showAuth(true, "Workstation secured. Sign in with the administrator account.");
  } catch (error) {
    errorLabel.textContent = error.message;
  } finally {
    setupForm.elements.password.value = "";
    setupForm.elements.setup_code.value = "";
    setBusy(setupForm, false);
  }
});

async function changeOwnPassword(event, form, errorId) {
  event.preventDefault();
  if (!form.reportValidity()) return;
  const errorLabel = document.getElementById(errorId);
  errorLabel.textContent = "";
  const payload = formPayload(form);
  if (payload.new_password !== payload.confirm_password) {
    errorLabel.textContent = "The new passwords do not match.";
    return;
  }
  delete payload.confirm_password;
  setBusy(form, true);
  try {
    await api("/api/v1/auth/password", { method: "POST", body: JSON.stringify(payload) });
    showAuth(true, "Password changed. All your sessions were revoked. Sign in with your new password.");
    broadcastSessionChange(crypto.randomUUID());
  } catch (error) {
    if (error.name !== "AbortError") errorLabel.textContent = error.message;
  } finally {
    for (const input of form.querySelectorAll("input[type='password']")) input.value = "";
    setBusy(form, false);
  }
}

passwordForm.addEventListener("submit", (event) => changeOwnPassword(event, passwordForm, "password-error"));
requiredPasswordForm.addEventListener("submit", (event) => changeOwnPassword(event, requiredPasswordForm, "required-password-error"));
document.querySelector("#required-password-logout").addEventListener("click", () => signOut());
document.querySelector("#account-button").addEventListener("click", () => {
  passwordForm.reset();
  document.querySelector("#password-error").textContent = "";
  document.querySelector("#account-identity").textContent = `${state.user.display_name} (@${state.user.username})`;
  accountDialog.showModal();
});
document.querySelector("#logout-all-button").addEventListener("click", () => signOut(true, "All your server sessions have been revoked. Sign in again to continue."));
document.querySelector("#retry-logout").addEventListener("click", retryLogout);
document.querySelector("#auth-history-refresh").addEventListener("click", () => loadAuthHistory(true));
document.querySelector("#auth-history-older").addEventListener("click", () => {
  if (authHistoryNext === null || authHistoryBusy) return;
  authHistoryCursors.push(authHistoryNext);
  void loadAuthHistory();
});
document.querySelector("#auth-history-newer").addEventListener("click", () => {
  if (authHistoryCursors.length <= 1 || authHistoryBusy) return;
  authHistoryCursors.pop();
  void loadAuthHistory();
});

userActionForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!selectedUserAction || !userActionForm.reportValidity()) return;
  const selection = selectedUserAction;
  const payload = formPayload(userActionForm);
  const errorLabel = document.querySelector("#user-action-error");
  errorLabel.textContent = "";
  setBusy(userActionForm, true);
  for (const button of document.querySelectorAll("#user-admin-list button")) button.disabled = true;
  let completed = false;
  try {
    const statusAction = ["suspend", "activate"].includes(selection.action);
    if (statusAction) payload.active = selection.action === "activate";
    await api(`/api/v1/users/${selection.user.user_id}/${statusAction ? "status" : selection.action}`, {
      method: statusAction ? "PATCH" : "POST", body: JSON.stringify(payload),
    });
    completed = true;
    userActionDialog.close();
    showToast(`${selection.label} completed for @${selection.user.username}. Reason: ${payload.reason}`);
    renderUsers(await api("/api/v1/users"));
    await loadAuthHistory(true);
  } catch (error) {
    if (error.name !== "AbortError") {
      if (completed) showToast("Account action completed. Refresh the account register to confirm its current state.");
      else errorLabel.textContent = error.message;
    }
  } finally {
    for (const input of userActionForm.querySelectorAll("input[type='password']")) input.value = "";
    setBusy(userActionForm, false);
    for (const button of document.querySelectorAll("#user-admin-list button")) button.disabled = false;
  }
});

caseCreateForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorLabel = document.querySelector("#case-create-error");
  errorLabel.textContent = "";
  setBusy(caseCreateForm, true);
  try {
    const created = await api("/api/v1/cases", {
      method: "POST",
      body: JSON.stringify(formPayload(caseCreateForm)),
    });
    caseCreateForm.reset();
    caseCreateDialog.close();
    await loadCases();
    showToast("Case registered and added to the protected activity chain.");
    await openCase(created.case_id);
  } catch (error) {
    errorLabel.textContent = error.message;
  } finally {
    setBusy(caseCreateForm, false);
  }
});

exhibitForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorLabel = document.querySelector("#exhibit-error");
  errorLabel.textContent = "";
  setBusy(exhibitForm, true);
  try {
    await api(`/api/v1/cases/${state.selectedCase.case_id}/exhibits`, {
      method: "POST",
      body: JSON.stringify(exhibitPayload(exhibitForm)),
    });
    exhibitForm.reset();
    exhibitDialog.close();
    showToast("Exhibit registered with intake and authority details.");
    await openCase(state.selectedCase.case_id);
  } catch (error) {
    errorLabel.textContent = error.message;
  } finally {
    setBusy(exhibitForm, false);
  }
});

evidenceForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorLabel = document.querySelector("#evidence-error");
  const payload = formPayload(evidenceForm);
  const file = document.querySelector("#evidence-file").files[0];
  errorLabel.textContent = "";
  if (!file) {
    errorLabel.textContent = "Select an evidence file.";
    return;
  }
  setBusy(evidenceForm, true);
  try {
    await api(
      `/api/v1/cases/${state.selectedCase.case_id}/exhibits/${payload.exhibit_id}/evidence`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/octet-stream",
          "X-ForenX-Filename": encodeURIComponent(file.name),
          "X-ForenX-Media-Kind": payload.media_kind,
        },
        body: file,
      },
    );
    evidenceForm.reset();
    evidenceDialog.close();
    showToast("Evidence copied, hashed, and locked read-only in the private vault.");
    await openCase(state.selectedCase.case_id);
  } catch (error) {
    errorLabel.textContent = error.message;
  } finally {
    setBusy(evidenceForm, false);
  }
});

bookmarkForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorLabel = document.querySelector("#bookmark-error");
  errorLabel.textContent = "";
  setBusy(bookmarkForm, true);
  try {
    const payload = formPayload(bookmarkForm);
    payload.timestamp_ms = state.bookmarkTimestampMs;
    await api(`/api/v1/evidence/${state.selectedEvidence.source_id}/bookmarks`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    const bookmarks = await api(
      `/api/v1/evidence/${state.selectedEvidence.source_id}/bookmarks`,
    );
    bookmarkForm.reset();
    bookmarkDialog.close();
    renderBookmarks(bookmarks);
    showToast("Examiner observation linked to the exact video position.");
  } catch (error) {
    errorLabel.textContent = error.message;
  } finally {
    setBusy(bookmarkForm, false);
  }
});

reportForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorLabel = document.querySelector("#report-error");
  errorLabel.textContent = "";
  setBusy(reportForm, true);
  try {
    const payload = formPayload(reportForm);
    const sourceId = payload.source_id;
    delete payload.source_id;
    payload.limitations = (payload.limitations || "")
      .split("\n")
      .map((value) => value.trim())
      .filter(Boolean);
    const report = await api(`/api/v1/evidence/${sourceId}/reports`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    reportForm.reset();
    reportDialog.close();
    showToast("Source verified and signed report package created.");
    await openCase(report.case_id);
  } catch (error) {
    errorLabel.textContent = error.message;
  } finally {
    setBusy(reportForm, false);
  }
});

biometricAuthorizationForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorLabel = document.querySelector("#biometric-authorization-error");
  errorLabel.textContent = "";
  setBusy(biometricAuthorizationForm, true);
  try {
    const payload = formPayload(biometricAuthorizationForm);
    const sourceId = payload.source_id;
    delete payload.source_id;
    payload.mode = "one-to-one";
    payload.retention_until = new Date(payload.retention_until).toISOString();
    await api(`/api/v1/evidence/${sourceId}/biometric-authorizations`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    biometricAuthorizationForm.reset();
    biometricAuthorizationDialog.close();
    showToast("Controlled face-analysis authorization added to the audit chain.");
    await openCase(state.selectedCase.case_id);
  } catch (error) {
    errorLabel.textContent = error.message;
  } finally {
    setBusy(biometricAuthorizationForm, false);
  }
});

userCreateForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!userCreateForm.reportValidity()) return;
  const errorLabel = document.querySelector("#user-create-error");
  errorLabel.textContent = "";
  setBusy(userCreateForm, true);
  try {
    await api("/api/v1/users", {
      method: "POST",
      body: JSON.stringify(formPayload(userCreateForm)),
    });
    userCreateForm.reset();
    renderUsers(await api("/api/v1/users"));
    showToast("Account created. A password change is required at first sign-in. Grant case access separately.");
    await loadAuthHistory(true);
  } catch (error) {
    errorLabel.textContent = error.message;
  } finally {
    userCreateForm.elements.password.value = "";
    setBusy(userCreateForm, false);
  }
});

caseTeamForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorLabel = document.querySelector("#case-team-error");
  errorLabel.textContent = "";
  setBusy(caseTeamForm, true);
  try {
    await api(`/api/v1/cases/${state.selectedCase.case_id}/assignments`, {
      method: "POST",
      body: JSON.stringify(formPayload(caseTeamForm)),
    });
    caseDetailDialog.close();
    await openCase(state.selectedCase.case_id);
    showToast("Case access granted and recorded in the audit chain.");
  } catch (error) {
    errorLabel.textContent = error.message;
  } finally {
    setBusy(caseTeamForm, false);
  }
});

transitionForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorLabel = document.querySelector("#transition-error");
  errorLabel.textContent = "";
  setBusy(transitionForm, true);
  try {
    const payload = formPayload(transitionForm);
    payload.expected_version = state.selectedCase.version;
    const updated = await api(`/api/v1/cases/${state.selectedCase.case_id}/transition`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    transitionForm.reset();
    caseDetailDialog.close();
    await loadCases();
    showToast(`Case moved to ${updated.status.replaceAll("-", " ")}.`);
    await openCase(updated.case_id);
  } catch (error) {
    errorLabel.textContent = error.message;
  } finally {
    setBusy(transitionForm, false);
  }
});

document.querySelector("#logout-button").addEventListener("click", () => signOut());

document.querySelector("#case-search").addEventListener("input", renderCases);
document.querySelector("#new-case-button").addEventListener("click", () => caseCreateDialog.showModal());
document.querySelector("[data-action='new-case']").addEventListener("click", () =>
  caseCreateDialog.showModal(),
);
document.querySelector("#add-exhibit-button").addEventListener("click", () => {
  caseDetailDialog.close();
  exhibitDialog.showModal();
});
document.querySelector("#ingest-evidence-button").addEventListener("click", () => {
  const select = document.querySelector("#evidence-exhibit");
  select.replaceChildren();
  for (const exhibit of state.selectedExhibits) {
    const option = document.createElement("option");
    option.value = exhibit.exhibit_id;
    option.textContent = `${exhibit.exhibit_number} · ${exhibit.device_type}`;
    select.append(option);
  }
  if (state.selectedExhibits.length === 0) {
    showToast("Register an exhibit before ingesting its evidence source.");
    return;
  }
  caseDetailDialog.close();
  evidenceDialog.showModal();
});
document.querySelector("#create-report-button").addEventListener("click", () => {
  const select = document.querySelector("#report-source");
  select.replaceChildren();
  for (const source of state.selectedEvidenceSources.filter(
    (record) => record.media_kind === "video-file",
  )) {
    const option = document.createElement("option");
    option.value = source.source_id;
    option.textContent = `${source.original_filename} · ${formatBytes(source.byte_size)}`;
    select.append(option);
  }
  caseDetailDialog.close();
  reportDialog.showModal();
});
document.querySelector("#authorize-biometric-button").addEventListener("click", () => {
  const select = document.querySelector("#biometric-source");
  select.replaceChildren();
  for (const source of state.selectedEvidenceSources.filter(
    (record) => record.media_kind === "video-file",
  )) {
    const option = document.createElement("option");
    option.value = source.source_id;
    option.textContent = `${source.original_filename} · ${formatBytes(source.byte_size)}`;
    select.append(option);
  }
  caseDetailDialog.close();
  biometricAuthorizationDialog.showModal();
});
document.querySelector("#start-recovery-scan").addEventListener("click", async () => {
  const button = document.querySelector("#start-recovery-scan");
  button.disabled = true;
  button.textContent = "Verifying and probing…";
  try {
    await api(
      `/api/v1/evidence/${state.selectedRecoverySource.source_id}/recovery-scans`,
      { method: "POST" },
    );
    await refreshRecoveryScans();
    showToast("Recovery scan stored with adapter and source-extent provenance.");
  } catch (error) {
    showToast(error.message);
  } finally {
    button.disabled = false;
    button.textContent = "Probe and enumerate";
  }
});
document.querySelector("#previous-frame").addEventListener("click", () => {
  const video = primaryVideoStream(state.currentInspection);
  const step = 1 / (video?.average_frame_rate || 25);
  evidencePlayer.pause();
  evidencePlayer.currentTime = Math.max(0, evidencePlayer.currentTime - step);
});
document.querySelector("#next-frame").addEventListener("click", () => {
  const video = primaryVideoStream(state.currentInspection);
  const step = 1 / (video?.average_frame_rate || 25);
  evidencePlayer.pause();
  evidencePlayer.currentTime = Math.min(
    evidencePlayer.duration || Number.POSITIVE_INFINITY,
    evidencePlayer.currentTime + step,
  );
});
document.querySelector("#bookmark-current").addEventListener("click", () => {
  state.bookmarkTimestampMs = Math.max(0, Math.round(evidencePlayer.currentTime * 1000));
  document.querySelector("#bookmark-time-display").value = formatTimecode(
    state.bookmarkTimestampMs / 1000,
  );
  bookmarkDialog.showModal();
});
document.querySelector("#detect-current-frame").addEventListener("click", async () => {
  const button = document.querySelector("#detect-current-frame");
  button.disabled = true;
  button.textContent = "Detecting locally…";
  try {
    await api(`/api/v1/evidence/${state.selectedEvidence.source_id}/face-detections`, {
      method: "POST",
      body: JSON.stringify({
        timestamp_ms: Math.max(0, Math.round(evidencePlayer.currentTime * 1000)),
      }),
    });
    const [runs, authorizations] = await Promise.all([
      api(`/api/v1/evidence/${state.selectedEvidence.source_id}/face-detections`),
      api(
        `/api/v1/evidence/${state.selectedEvidence.source_id}/biometric-authorizations`,
      ),
    ]);
    state.currentFaceDetections = runs;
    state.currentBiometricAuthorizations = authorizations;
    state.trackStartTimestampMs = Math.min(
      state.trackStartTimestampMs,
      ...runs.map((run) => run.observed_timestamp_ms),
    );
    state.trackEndTimestampMs = Math.max(
      state.trackEndTimestampMs,
      ...runs.map((run) => run.observed_timestamp_ms),
    );
    renderFaceDetections(runs, authorizations);
    renderFaceTracking(state.currentFaceTrackingRuns, authorizations, runs);
    showToast("Face detection stored with frame, model, and authorization provenance.");
  } catch (error) {
    showToast(error.message);
  } finally {
    button.textContent = "Detect at current frame";
    button.disabled = !activeAuthorization(state.currentBiometricAuthorizations);
  }
});

document.querySelector("#set-track-start").addEventListener("click", () => {
  state.trackStartTimestampMs = Math.max(0, Math.round(evidencePlayer.currentTime * 1000));
  if (state.trackEndTimestampMs < state.trackStartTimestampMs) {
    state.trackEndTimestampMs = state.trackStartTimestampMs;
  }
  renderFaceTracking(
    state.currentFaceTrackingRuns,
    state.currentBiometricAuthorizations,
    state.currentFaceDetections,
  );
});

document.querySelector("#set-track-end").addEventListener("click", () => {
  state.trackEndTimestampMs = Math.max(0, Math.round(evidencePlayer.currentTime * 1000));
  if (state.trackStartTimestampMs > state.trackEndTimestampMs) {
    state.trackStartTimestampMs = state.trackEndTimestampMs;
  }
  renderFaceTracking(
    state.currentFaceTrackingRuns,
    state.currentBiometricAuthorizations,
    state.currentFaceDetections,
  );
});

document.querySelector("#create-face-tracks").addEventListener("click", async () => {
  const button = document.querySelector("#create-face-tracks");
  button.disabled = true;
  button.textContent = "Linking observations…";
  try {
    await api(`/api/v1/evidence/${state.selectedEvidence.source_id}/face-tracks`, {
      method: "POST",
      body: JSON.stringify({
        start_timestamp_ms: state.trackStartTimestampMs,
        end_timestamp_ms: state.trackEndTimestampMs,
        iou_threshold: 0.25,
        max_gap_ms: 2000,
      }),
    });
    state.currentFaceTrackingRuns = await api(
      `/api/v1/evidence/${state.selectedEvidence.source_id}/face-tracks`,
    );
    renderFaceTracking(
      state.currentFaceTrackingRuns,
      state.currentBiometricAuthorizations,
      state.currentFaceDetections,
    );
    showToast("Geometric tracks stored with source-frame and detection provenance.");
  } catch (error) {
    showToast(error.message);
  } finally {
    button.textContent = "Build geometric tracks";
    button.disabled = false;
    renderFaceTracking(
      state.currentFaceTrackingRuns,
      state.currentBiometricAuthorizations,
      state.currentFaceDetections,
    );
  }
});

evidencePlayer.addEventListener("timeupdate", () => {
  document.querySelector("#current-timecode").textContent = formatTimecode(
    evidencePlayer.currentTime,
  );
});
evidencePlayer.addEventListener("error", () => {
  const error = document.querySelector("#player-error");
  error.textContent =
    "This browser cannot decode the original container or codec. The source remains preserved; a verified playable derivative will be required.";
  error.hidden = false;
});
videoDialog.addEventListener("close", () => {
  evidencePlayer.pause();
  evidencePlayer.removeAttribute("src");
  evidencePlayer.load();
  document.querySelector("#current-timecode").textContent = "00:00:00.000";
});

for (const closeButton of document.querySelectorAll("[data-close-dialog]")) {
  closeButton.addEventListener("click", () => closeButton.closest("dialog").close());
}

for (const dialog of document.querySelectorAll("dialog")) {
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
  dialog.addEventListener("close", () => {
    for (const input of dialog.querySelectorAll("input[type='password']")) input.value = "";
  });
}

for (const navItem of document.querySelectorAll(".nav-item")) {
  navItem.addEventListener("click", async () => {
    const view = navItem.dataset.view;
    if (view === "vendors") await loadVendors();
    else if (view === "users") await loadUsers();
    else if (capabilityContent[view]) openCapability(view);
  });
}

async function start() {
  loginForm.hidden = true;
  setupForm.hidden = true;
  setAuthStatus("Checking the local service and account session…");
  try {
    if (state.token) {
      try { checkBrowserSession(localStorage.getItem("forenx.browser-session")); } catch (_error) { /* Session verification still runs if browser storage is unavailable. */ }
      if (!state.token) return;
      checkSessionTime();
      if (!state.token) return;
      state.user = await api("/api/v1/auth/me");
      activityRequestAt = Date.now();
      showWorkspace();
      if (!state.user.must_change_password) await loadCases();
      return;
    }
    const setup = await api("/api/v1/setup/status");
    showAuth(setup.initialized);
  } catch (error) {
    if (error.status !== 401 && error.name !== "AbortError") {
      showAuth(true, "The local service or session could not be verified. Sign in again when the service is available.");
    }
  }
}

for (const eventName of ["pointerdown", "keydown", "wheel", "touchstart"]) {
  document.addEventListener(eventName, recordActivity, { passive: true });
}
sessionChannel?.addEventListener("message", (event) => checkBrowserSession(event.data?.marker));
window.addEventListener("storage", (event) => {
  if (event.key === "forenx.browser-session") checkBrowserSession(event.newValue);
});
document.addEventListener("visibilitychange", () => {
  if (document.hidden) return;
  try { checkBrowserSession(localStorage.getItem("forenx.browser-session")); } catch (_error) { /* BroadcastChannel remains available. */ }
  checkSessionTime();
});
window.addEventListener("pageshow", (event) => {
  if (event.persisted) {
    // Re-enter through verified startup after a browser back/forward cache restore.
    window.location.reload();
  }
});

start();
