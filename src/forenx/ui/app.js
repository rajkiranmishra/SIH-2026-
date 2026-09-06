"use strict";

const state = {
  token: sessionStorage.getItem("forenx.session"),
  user: JSON.parse(sessionStorage.getItem("forenx.user") || "null"),
  cases: [],
  selectedCase: null,
  selectedExhibits: [],
};

const rolePermissions = {
  "intake-officer": new Set([
    "case:create",
    "case:read",
    "exhibit:create",
    "evidence:ingest",
  ]),
  examiner: new Set(["case:read", "case:process"]),
  supervisor: new Set(["case:read", "case:process", "case:approve"]),
  investigator: new Set(["case:read"]),
  auditor: new Set(["case:read"]),
  administrator: new Set([
    "case:create",
    "case:read",
    "exhibit:create",
    "evidence:ingest",
    "case:process",
    "case:approve",
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
  EXHIBIT_REGISTERED: "Exhibit registered",
  CASE_STATUS_CHANGED: "Workflow stage changed",
  EVIDENCE_INGEST_STARTED: "Evidence intake started",
  EVIDENCE_INGEST_COMPLETED: "Evidence intake completed",
  EVIDENCE_INGEST_FAILED: "Evidence intake failed",
  EVIDENCE_INTEGRITY_VERIFIED: "Evidence integrity verified",
  EVIDENCE_INTEGRITY_FAILED: "Evidence integrity warning",
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
const transitionForm = document.querySelector("#transition-form");
const vendorDialog = document.querySelector("#vendor-dialog");
const capabilityDialog = document.querySelector("#capability-dialog");
const toast = document.querySelector("#toast");

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (typeof options.body === "string" && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (state.token) headers.set("Authorization", `Bearer ${state.token}`);
  const response = await fetch(path, { ...options, headers });
  if (response.status === 204) return null;
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const details = Array.isArray(payload.detail)
      ? payload.detail.map((item) => item.msg).join("; ")
      : payload.detail;
    const error = new Error(details || "The operation could not be completed");
    error.status = response.status;
    throw error;
  }
  return payload;
}

function can(permission) {
  return rolePermissions[state.user?.role]?.has(permission) || false;
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

function showAuth(initialized) {
  state.token = null;
  state.user = null;
  sessionStorage.removeItem("forenx.session");
  sessionStorage.removeItem("forenx.user");
  authView.hidden = false;
  workspace.hidden = true;
  loginForm.hidden = !initialized;
  setupForm.hidden = initialized;
}

function showWorkspace() {
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
    if (error.status === 401) {
      showAuth(true);
      return;
    }
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
    appendTextElement(identity, "span", record.media_kind.replaceAll("-", " "));
    appendTextElement(identity, "strong", record.original_filename);
    const integrity = document.createElement("div");
    appendTextElement(integrity, "span", `${formatBytes(record.byte_size)} · SHA-256`);
    appendTextElement(integrity, "code", record.sha256);
    item.append(identity, integrity);
    if (can("case:process")) {
      const verifyButton = appendTextElement(item, "button", "Verify integrity", "button button-secondary verify-button");
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
          verifyButton.textContent = "Verify integrity";
        }
      });
    }
    list.append(item);
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
    const [caseRecord, exhibits, evidence, events, verification] = await Promise.all([
      api(`/api/v1/cases/${caseId}`),
      api(`/api/v1/cases/${caseId}/exhibits`),
      api(`/api/v1/cases/${caseId}/evidence`),
      api(`/api/v1/cases/${caseId}/activity`),
      api(`/api/v1/cases/${caseId}/activity/verify`),
    ]);
    state.selectedCase = caseRecord;
    state.selectedExhibits = exhibits;
    document.querySelector("#detail-reference").textContent = caseRecord.case_reference;
    document.querySelector("#detail-agency").textContent = caseRecord.agency;
    document.querySelector("#detail-status").textContent = caseRecord.status.replaceAll("-", " ");
    document.querySelector("#detail-officer").textContent = caseRecord.investigating_officer;
    document.querySelector("#detail-station").textContent = caseRecord.police_station || "Not supplied";
    document.querySelector("#detail-classification").textContent = caseRecord.classification;
    document.querySelector("#detail-updated").textContent = formatDate(caseRecord.updated_at);
    document.querySelector("#add-exhibit-button").hidden = !can("exhibit:create");
    document.querySelector("#ingest-evidence-button").hidden = !can("evidence:ingest");
    renderExhibits(exhibits);
    renderEvidence(evidence);
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
  const errorLabel = document.querySelector("#login-error");
  errorLabel.textContent = "";
  setBusy(loginForm, true);
  try {
    const session = await api("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify(formPayload(loginForm)),
    });
    state.token = session.token;
    state.user = session.user;
    sessionStorage.setItem("forenx.session", state.token);
    sessionStorage.setItem("forenx.user", JSON.stringify(state.user));
    loginForm.reset();
    showWorkspace();
    await loadCases();
  } catch (error) {
    errorLabel.textContent = error.message;
  } finally {
    setBusy(loginForm, false);
  }
});

setupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorLabel = document.querySelector("#setup-error");
  errorLabel.textContent = "";
  setBusy(setupForm, true);
  try {
    const payload = formPayload(setupForm);
    await api("/api/v1/setup", { method: "POST", body: JSON.stringify(payload) });
    setupForm.reset();
    showAuth(true);
    showToast("Workstation secured. Sign in with the administrator account.");
  } catch (error) {
    errorLabel.textContent = error.message;
  } finally {
    setBusy(setupForm, false);
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

document.querySelector("#logout-button").addEventListener("click", async () => {
  try {
    await api("/api/v1/auth/logout", { method: "POST" });
  } catch (_error) {
    // Clear local credentials even if the server session already expired.
  }
  showAuth(true);
});

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

for (const closeButton of document.querySelectorAll("[data-close-dialog]")) {
  closeButton.addEventListener("click", () => closeButton.closest("dialog").close());
}

for (const dialog of document.querySelectorAll("dialog")) {
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
}

for (const navItem of document.querySelectorAll(".nav-item")) {
  navItem.addEventListener("click", async () => {
    const view = navItem.dataset.view;
    if (view === "vendors") await loadVendors();
    else if (capabilityContent[view]) openCapability(view);
  });
}

async function start() {
  if (state.token && state.user) {
    showWorkspace();
    await loadCases();
    return;
  }
  try {
    const setup = await api("/api/v1/setup/status");
    showAuth(setup.initialized);
  } catch (_error) {
    showAuth(true);
    document.querySelector("#login-error").textContent = "The local service is not available.";
  }
}

start();
