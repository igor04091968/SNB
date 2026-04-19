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

document.getElementById("snapshots-file").addEventListener("change", event => loadFileInto(event, snapshotsText));
document.getElementById("activity-file").addEventListener("change", event => loadFileInto(event, activityText));
loadSampleButton.addEventListener("click", () => {
  snapshotsText.value = sampleSnapshots;
  activityText.value = sampleWindows;
  statusLine.textContent = "Sample data loaded.";
});
analyzeButton.addEventListener("click", analyze);

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

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
