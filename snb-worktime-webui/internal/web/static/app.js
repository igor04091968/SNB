const sampleSnapshots = `{"server":"srv-1","user":"alice","session_id":"3","state":"active","idle_seconds":5,"client_ip":"10.0.0.10","captured_at":"2026-04-18T09:00:00Z"}
{"server":"srv-1","user":"alice","session_id":"3","state":"active","idle_seconds":10,"client_ip":"10.0.0.10","captured_at":"2026-04-18T09:01:00Z"}
{"server":"srv-1","user":"alice","session_id":"3","state":"active","idle_seconds":125,"client_ip":"10.0.0.10","captured_at":"2026-04-18T09:03:00Z"}
{"server":"srv-1","user":"alice","session_id":"3","state":"disconnected","idle_seconds":0,"client_ip":"10.0.0.10","captured_at":"2026-04-18T09:05:00Z"}
{"server":"srv-1","user":"alice","session_id":"3","state":"active","idle_seconds":20,"client_ip":"10.0.0.10","captured_at":"2026-04-18T09:06:00Z"}
{"server":"srv-1","user":"alice","session_id":"3","state":"active","idle_seconds":15,"client_ip":"10.0.0.10","captured_at":"2026-04-18T09:08:00Z"}
{"server":"srv-2","user":"bob","session_id":"8","state":"active","idle_seconds":0,"client_ip":"10.0.0.11","captured_at":"2026-04-18T09:00:00Z"}
{"server":"srv-2","user":"bob","session_id":"8","state":"active","idle_seconds":0,"client_ip":"10.0.0.11","captured_at":"2026-04-18T09:02:00Z"}
{"server":"srv-2","user":"bob","session_id":"8","state":"active","idle_seconds":0,"client_ip":"10.0.0.11","captured_at":"2026-04-18T09:14:00Z"}`;

const sampleWindows = `{"server":"srv-1","client_ip":"10.0.0.10","started_at":"2026-04-18T09:00:00Z","ended_at":"2026-04-18T09:02:30Z","source":"workstation"}
{"server":"srv-2","user":"bob","started_at":"2026-04-18T09:00:00Z","ended_at":"2026-04-18T09:01:00Z","source":"network"}`;

const snapshotsText = document.getElementById("snapshots-text");
const activityText = document.getElementById("activity-text");
const idleThreshold = document.getElementById("idle-threshold");
const maxGap = document.getElementById("max-gap");
const analyzeButton = document.getElementById("analyze-button");
const loadSampleButton = document.getElementById("load-sample");
const statusLine = document.getElementById("status-line");
const resultsBody = document.getElementById("results-body");
const summaryMeta = document.getElementById("summary-meta");
const warningsBox = document.getElementById("warnings");
const inventoryStatus = document.getElementById("inventory-status");
const linuxServersBody = document.getElementById("linux-servers-body");
const linuxAuditBody = document.getElementById("linux-audit-body");
const linuxAuditWarnings = document.getElementById("linux-audit-warnings");
const linuxAuditStatus = document.getElementById("linux-audit-status");
const linuxAuditMeta = document.getElementById("linux-audit-meta");

const linuxServerId = document.getElementById("linux-server-id");
const linuxName = document.getElementById("linux-name");
const linuxHost = document.getElementById("linux-host");
const linuxPort = document.getElementById("linux-port");
const linuxUsername = document.getElementById("linux-username");
const linuxPassword = document.getElementById("linux-password");
const linuxKeyPassphrase = document.getElementById("linux-key-passphrase");
const linuxPrivateKey = document.getElementById("linux-private-key");
const linuxNotes = document.getElementById("linux-notes");
const saveLinuxServerButton = document.getElementById("save-linux-server");
const resetLinuxServerButton = document.getElementById("reset-linux-server");
const runLinuxAuditButton = document.getElementById("run-linux-audit");
const linuxAuditSince = document.getElementById("linux-audit-since");
const linuxAuditUntil = document.getElementById("linux-audit-until");

let linuxServers = [];

document.getElementById("snapshots-file").addEventListener("change", event => loadFileInto(event, snapshotsText));
document.getElementById("activity-file").addEventListener("change", event => loadFileInto(event, activityText));
loadSampleButton.addEventListener("click", () => {
  snapshotsText.value = sampleSnapshots;
  activityText.value = sampleWindows;
  statusLine.textContent = "Sample data loaded.";
});
analyzeButton.addEventListener("click", analyze);
saveLinuxServerButton.addEventListener("click", saveLinuxServer);
resetLinuxServerButton.addEventListener("click", resetLinuxServerForm);
runLinuxAuditButton.addEventListener("click", runLinuxAudit);

setDefaultAuditWindow();
loadLinuxServers();

async function analyze() {
  analyzeButton.disabled = true;
  statusLine.textContent = "Analyzing...";

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        snapshots_text: snapshotsText.value,
        activity_windows_text: activityText.value,
        idle_threshold_sec: Number(idleThreshold.value),
        max_gap_sec: Number(maxGap.value)
      })
    });

    if (!response.ok) {
      const message = await response.text();
      throw new Error(message || "Analysis failed");
    }

    const payload = await response.json();
    renderResults(payload.rows);
    renderWarnings(payload.warnings);
    summaryMeta.textContent = `${payload.rows.length} users, ${payload.snapshots} snapshots, ${payload.windows} activity windows`;
    statusLine.textContent = "Analysis completed.";
  } catch (error) {
    statusLine.textContent = `Error: ${error.message}`;
    renderResults([]);
    renderWarnings([]);
    summaryMeta.textContent = "No analysis available.";
  } finally {
    analyzeButton.disabled = false;
  }
}

function renderResults(rows) {
  if (!rows.length) {
    resultsBody.innerHTML = `<tr><td colspan="9" class="empty-state">No rows to display.</td></tr>`;
    return;
  }

  resultsBody.innerHTML = rows.map(row => `
    <tr>
      <td>${escapeHtml(row.server || "-")}</td>
      <td>${escapeHtml(row.user)}</td>
      <td>${escapeHtml(row.worked_human)}</td>
      <td>${escapeHtml(row.confirmed_human)}</td>
      <td>${escapeHtml(row.unconfirmed_human)}</td>
      <td>${escapeHtml(row.idle_human)}</td>
      <td>${escapeHtml(row.disconnected_human)}</td>
      <td>${escapeHtml(row.unknown_human)}</td>
      <td>${escapeHtml(String(row.samples))}</td>
    </tr>
  `).join("");
}

function renderWarnings(warnings) {
  if (!warnings.length) {
    warningsBox.classList.add("hidden");
    warningsBox.innerHTML = "";
    return;
  }

  warningsBox.classList.remove("hidden");
  warningsBox.innerHTML = warnings.map(item => `<div>${escapeHtml(item)}</div>`).join("");
}

async function loadFileInto(event, target) {
  const [file] = event.target.files;
  if (!file) {
    return;
  }

  target.value = await file.text();
  statusLine.textContent = `${file.name} loaded.`;
}

async function loadLinuxServers() {
  try {
    const response = await fetch("/api/linux-servers");
    if (!response.ok) {
      throw new Error("Failed to load Linux servers");
    }
    const payload = await response.json();
    linuxServers = payload.servers || [];
    renderLinuxServers();
    inventoryStatus.textContent = `${linuxServers.length} SSH targets saved.`;
  } catch (error) {
    inventoryStatus.textContent = `Error: ${error.message}`;
  }
}

function renderLinuxServers() {
  if (!linuxServers.length) {
    linuxServersBody.innerHTML = `<tr><td colspan="7" class="empty-state">No Linux servers yet.</td></tr>`;
    return;
  }

  linuxServersBody.innerHTML = linuxServers.map(server => `
    <tr>
      <td><input class="linux-server-check" type="checkbox" value="${escapeHtml(server.id)}"></td>
      <td>${escapeHtml(server.name || "-")}</td>
      <td>${escapeHtml(server.host)}:${escapeHtml(String(server.port || 22))}</td>
      <td>${escapeHtml(server.username)}</td>
      <td>${describeAuth(server)}</td>
      <td>${escapeHtml(formatDate(server.updated_at))}</td>
      <td class="row-actions">
        <button class="ghost-button small-button" type="button" onclick="editLinuxServer('${escapeJs(server.id)}')">Edit</button>
        <button class="ghost-button small-button danger-button" type="button" onclick="deleteLinuxServer('${escapeJs(server.id)}')">Delete</button>
      </td>
    </tr>
  `).join("");
}

async function saveLinuxServer() {
  saveLinuxServerButton.disabled = true;
  inventoryStatus.textContent = "Saving Linux server...";

  try {
    const response = await fetch("/api/linux-servers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        id: linuxServerId.value,
        name: linuxName.value,
        host: linuxHost.value,
        port: Number(linuxPort.value),
        username: linuxUsername.value,
        password: linuxPassword.value,
        private_key_pem: linuxPrivateKey.value,
        private_key_passphrase: linuxKeyPassphrase.value,
        notes: linuxNotes.value
      })
    });
    if (!response.ok) {
      throw new Error(await response.text() || "Failed to save Linux server");
    }
    resetLinuxServerForm();
    await loadLinuxServers();
    inventoryStatus.textContent = "Linux server saved.";
  } catch (error) {
    inventoryStatus.textContent = `Error: ${error.message}`;
  } finally {
    saveLinuxServerButton.disabled = false;
  }
}

function editLinuxServer(id) {
  const server = linuxServers.find(item => item.id === id);
  if (!server) {
    return;
  }
  linuxServerId.value = server.id || "";
  linuxName.value = server.name || "";
  linuxHost.value = server.host || "";
  linuxPort.value = server.port || 22;
  linuxUsername.value = server.username || "";
  linuxPassword.value = server.password || "";
  linuxPrivateKey.value = server.private_key_pem || "";
  linuxKeyPassphrase.value = server.private_key_passphrase || "";
  linuxNotes.value = server.notes || "";
  inventoryStatus.textContent = `Editing ${server.name || server.host}.`;
}

async function deleteLinuxServer(id) {
  const server = linuxServers.find(item => item.id === id);
  if (!server) {
    return;
  }
  if (!window.confirm(`Delete ${server.name || server.host}?`)) {
    return;
  }
  try {
    const response = await fetch(`/api/linux-servers?id=${encodeURIComponent(id)}`, { method: "DELETE" });
    if (!response.ok) {
      throw new Error(await response.text() || "Delete failed");
    }
    await loadLinuxServers();
    inventoryStatus.textContent = "Linux server deleted.";
  } catch (error) {
    inventoryStatus.textContent = `Error: ${error.message}`;
  }
}

function resetLinuxServerForm() {
  linuxServerId.value = "";
  linuxName.value = "";
  linuxHost.value = "";
  linuxPort.value = "22";
  linuxUsername.value = "";
  linuxPassword.value = "";
  linuxPrivateKey.value = "";
  linuxKeyPassphrase.value = "";
  linuxNotes.value = "";
}

async function runLinuxAudit() {
  const selected = Array.from(document.querySelectorAll(".linux-server-check:checked")).map(item => item.value);
  if (!selected.length) {
    linuxAuditStatus.textContent = "Select at least one Linux server.";
    return;
  }

  runLinuxAuditButton.disabled = true;
  linuxAuditStatus.textContent = "Running remote Linux audit...";

  try {
    const response = await fetch("/api/linux-audit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        server_ids: selected,
        since: toRFC3339(linuxAuditSince.value),
        until: toRFC3339(linuxAuditUntil.value)
      })
    });
    if (!response.ok) {
      throw new Error(await response.text() || "Linux audit failed");
    }

    const payload = await response.json();
    renderLinuxAuditRows(payload.rows || []);
    renderBoxWarnings(linuxAuditWarnings, payload.warnings || []);
    linuxAuditMeta.textContent = `${payload.successful_hosts}/${payload.scanned_servers} hosts scanned`;
    linuxAuditStatus.textContent = "Linux audit completed.";
  } catch (error) {
    linuxAuditStatus.textContent = `Error: ${error.message}`;
    renderLinuxAuditRows([]);
    renderBoxWarnings(linuxAuditWarnings, []);
    linuxAuditMeta.textContent = "No remote audit available.";
  } finally {
    runLinuxAuditButton.disabled = false;
  }
}

function renderLinuxAuditRows(rows) {
  if (!rows.length) {
    linuxAuditBody.innerHTML = `<tr><td colspan="9" class="empty-state">No Linux audit rows.</td></tr>`;
    return;
  }

  linuxAuditBody.innerHTML = rows.map(row => `
    <tr>
      <td>${escapeHtml(row.server)}</td>
      <td>${escapeHtml(row.user)}</td>
      <td>${escapeHtml(row.session_human)}</td>
      <td>${escapeHtml(row.open_human)}</td>
      <td>${escapeHtml(String(row.session_count))} / ${escapeHtml(String(row.open_sessions))}</td>
      <td>${escapeHtml(String(row.evidence_count))}</td>
      <td>${escapeHtml(row.source_summary || "-")}</td>
      <td>${escapeHtml(formatDate(row.first_seen))}</td>
      <td>${escapeHtml(formatDate(row.last_seen))}</td>
    </tr>
  `).join("");
}

function renderBoxWarnings(element, warnings) {
  if (!warnings.length) {
    element.classList.add("hidden");
    element.innerHTML = "";
    return;
  }
  element.classList.remove("hidden");
  element.innerHTML = warnings.map(item => `<div>${escapeHtml(item)}</div>`).join("");
}

function describeAuth(server) {
  const methods = [];
  if (server.password) {
    methods.push("password");
  }
  if (server.private_key_pem) {
    methods.push("key");
  }
  return escapeHtml(methods.join(" + ") || "none");
}

function setDefaultAuditWindow() {
  const now = new Date();
  const before = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  linuxAuditUntil.value = toDateTimeLocal(now);
  linuxAuditSince.value = toDateTimeLocal(before);
}

function toDateTimeLocal(date) {
  const pad = value => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function toRFC3339(value) {
  if (!value) {
    return "";
  }
  return new Date(value).toISOString();
}

function formatDate(value) {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}

function escapeJs(value) {
  return value.replaceAll("\\", "\\\\").replaceAll("'", "\\'");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

window.editLinuxServer = editLinuxServer;
window.deleteLinuxServer = deleteLinuxServer;
