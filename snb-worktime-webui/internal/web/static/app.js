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
const hrReportMeta = document.getElementById("hr-report-meta");
const hrReportStatus = document.getElementById("hr-report-status");
const hrReportPreview = document.getElementById("hr-report-preview");
const downloadHRReportButton = document.getElementById("download-hr-report");
const inventoryStatus = document.getElementById("inventory-status");
const linuxServersBody = document.getElementById("linux-servers-body");
const linuxAuditBody = document.getElementById("linux-audit-body");
const linuxAuditWarnings = document.getElementById("linux-audit-warnings");
const linuxAuditStatus = document.getElementById("linux-audit-status");
const linuxAuditMeta = document.getElementById("linux-audit-meta");
const filterSinceDate = document.getElementById("filter-since-date");
const filterUntilDate = document.getElementById("filter-until-date");
const defaultIntervalStart = document.getElementById("default-interval-start");
const defaultIntervalEnd = document.getElementById("default-interval-end");
const useOperatorInterval = document.getElementById("use-operator-interval");
const operatorIntervalStart = document.getElementById("operator-interval-start");
const operatorIntervalEnd = document.getElementById("operator-interval-end");
const intervalEffectiveLabel = document.getElementById("interval-effective-label");

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

let linuxServers = [];
let hrReportDownloadUrl = "";
const intervalStorageKey = "snb-worktime-interval-defaults";

document.getElementById("snapshots-file").addEventListener("change", event => loadFileInto(event, snapshotsText));
document.getElementById("activity-file").addEventListener("change", event => loadFileInto(event, activityText));
loadSampleButton.addEventListener("click", () => {
  snapshotsText.value = sampleSnapshots;
  activityText.value = sampleWindows;
  statusLine.textContent = "Пример загружен.";
});
analyzeButton.addEventListener("click", analyze);
saveLinuxServerButton.addEventListener("click", saveLinuxServer);
resetLinuxServerButton.addEventListener("click", resetLinuxServerForm);
runLinuxAuditButton.addEventListener("click", runLinuxAudit);
downloadHRReportButton.addEventListener("click", downloadHRReport);
defaultIntervalStart.addEventListener("change", persistDefaultIntervals);
defaultIntervalEnd.addEventListener("change", persistDefaultIntervals);
useOperatorInterval.addEventListener("change", updateEffectiveIntervalLabel);
operatorIntervalStart.addEventListener("change", updateEffectiveIntervalLabel);
operatorIntervalEnd.addEventListener("change", updateEffectiveIntervalLabel);

hydrateIntervalDefaults();
setDefaultDateRange();
updateEffectiveIntervalLabel();
loadLinuxServers();

async function analyze() {
  analyzeButton.disabled = true;
  statusLine.textContent = "Идет расчет...";

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        snapshots_text: snapshotsText.value,
        activity_windows_text: activityText.value,
        idle_threshold_sec: Number(idleThreshold.value),
        max_gap_sec: Number(maxGap.value),
        since_date: filterSinceDate.value,
        until_date: filterUntilDate.value,
        interval_start: effectiveInterval().start,
        interval_end: effectiveInterval().end
      })
    });

    if (!response.ok) {
      const message = await response.text();
      throw new Error(message || "Ошибка расчета");
    }

    const payload = await response.json();
    renderResults(payload.rows);
    renderWarnings(payload.warnings);
    summaryMeta.textContent = `${payload.rows.length} сотрудников, ${payload.snapshots} записей сессий, ${payload.windows} интервалов активности`;
    renderHRReport(payload);
    statusLine.textContent = "Расчет завершен.";
  } catch (error) {
    statusLine.textContent = `Ошибка: ${error.message}`;
    renderResults([]);
    renderWarnings([]);
    resetHRReport();
    summaryMeta.textContent = "Данных для сводки нет.";
  } finally {
    analyzeButton.disabled = false;
  }
}

function renderResults(rows) {
  if (!rows.length) {
    resultsBody.innerHTML = `<tr><td colspan="9" class="empty-state">Нет строк для показа.</td></tr>`;
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
  warnings = Array.isArray(warnings) ? warnings : [];
  if (!warnings.length) {
    warningsBox.classList.add("hidden");
    warningsBox.innerHTML = "";
    return;
  }

  warningsBox.classList.remove("hidden");
  warningsBox.innerHTML = warnings.map(item => `<div>${escapeHtml(item)}</div>`).join("");
}

function renderHRReport(payload) {
  const rows = Array.isArray(payload?.rows) ? payload.rows : [];
  if (!rows.length) {
    resetHRReport();
    hrReportStatus.textContent = "Отчет не создан.";
    return;
  }

  const totals = rows.reduce((acc, row) => {
    acc.worked += Number(row.worked_minutes || 0);
    acc.confirmed += Number(row.confirmed_minutes || 0);
    acc.unconfirmed += Number(row.unconfirmed_minutes || 0);
    acc.idle += Number(row.idle_minutes || 0);
    acc.disconnected += Number(row.disconnected_minutes || 0);
    acc.unknown += Number(row.unknown_minutes || 0);
    return acc;
  }, { worked: 0, confirmed: 0, unconfirmed: 0, idle: 0, disconnected: 0, unknown: 0 });

  const period = `${filterSinceDate.value || "-"} .. ${filterUntilDate.value || "-"}`;
  const effective = effectiveInterval();
  const lines = [
    "Отчет для кадровика",
    `Период: ${period}`,
    `Рабочий интервал: ${effective.start || "-"}-${effective.end || "-"}`,
    `Сотрудников: ${rows.length}`,
    `Записей сессий: ${payload.snapshots || 0}`,
    `Интервалов активности: ${payload.windows || 0}`,
    "",
    `Всего работа: ${humanizeMinutes(totals.worked)}`,
    `Всего подтверждено: ${humanizeMinutes(totals.confirmed)}`,
    `Всего без подтверждения: ${humanizeMinutes(totals.unconfirmed)}`,
    `Всего простой: ${humanizeMinutes(totals.idle)}`,
    `Всего отключен: ${humanizeMinutes(totals.disconnected)}`,
    `Всего неясно: ${humanizeMinutes(totals.unknown)}`,
    "",
    "По сотрудникам:"
  ];

  for (const row of rows) {
    lines.push(
      `${row.user} | сервер=${row.server || "-"} | работа=${row.worked_human} | подтверждено=${row.confirmed_human} | без подтверждения=${row.unconfirmed_human} | простой=${row.idle_human} | отключен=${row.disconnected_human} | неясно=${row.unknown_human} | точек=${row.samples}`
    );
  }

  hrReportPreview.value = lines.join("\n");
  hrReportMeta.textContent = `${rows.length} сотрудников, период ${period}, интервал ${effective.start}-${effective.end}`;
  hrReportStatus.textContent = "Отчет создан автоматически.";
  updateHRReportDownload(buildHRReportCSV(rows, payload, period, effective));
}

function renderLinuxAuditHRReport(payload) {
  const rows = Array.isArray(payload?.rows) ? payload.rows : [];
  const period = `${filterSinceDate.value || "-"} .. ${filterUntilDate.value || "-"}`;
  const effective = effectiveInterval();
  if (!rows.length) {
    resetHRReport();
    hrReportStatus.textContent = "Отчет по проверке Linux не создан.";
    return;
  }

  const sessionRows = rows.filter(row => row.has_sessions || Number(row.session_minutes || 0) > 0 || Number(row.session_count || 0) > 0);
  const evidenceRows = rows.filter(row => !(row.has_sessions || Number(row.session_minutes || 0) > 0 || Number(row.session_count || 0) > 0));

  const totalSessionMinutes = sessionRows.reduce((sum, row) => sum + Number(row.session_minutes || 0), 0);
  const totalCommandMinutes = sessionRows.reduce((sum, row) => sum + Number(row.command_minutes || 0), 0);
  const totalCodingMinutes = sessionRows.reduce((sum, row) => sum + Number(row.coding_minutes || 0), 0);
  const totalConfigMinutes = sessionRows.reduce((sum, row) => sum + Number(row.config_minutes || 0), 0);
  const totalActions = sessionRows.reduce((sum, row) => sum + Number(row.command_count || 0), 0);
  const totalOpenMinutes = sessionRows.reduce((sum, row) => sum + Number(row.open_minutes || 0), 0);
  const totalEvidence = rows.reduce((sum, row) => sum + Number(row.evidence_count || 0), 0);

  const lines = [
    "Отчет для кадровика по проверке Linux",
    `Период: ${period}`,
    `Рабочий интервал: ${effective.start || "-"}-${effective.end || "-"}`,
    `Проверено серверов: ${payload.successful_hosts || 0}/${payload.scanned_servers || 0}`,
    `Учетных записей с рабочими сессиями: ${sessionRows.length}`,
    `Служебных учетных записей без сессий: ${evidenceRows.length}`,
    "",
    `Общее время сессий: ${humanizeMinutes(totalSessionMinutes)}`,
    `Подтвержденная работа в оболочке: ${humanizeMinutes(totalCommandMinutes)}`,
    `Подтвержденная разработка: ${humanizeMinutes(totalCodingMinutes)}`,
    `Подтвержденная работа с конфигами: ${humanizeMinutes(totalConfigMinutes)}`,
    `Подтвержденных действий: ${totalActions}`,
    `Сейчас открыто: ${humanizeMinutes(totalOpenMinutes)}`,
    `Всего событий: ${totalEvidence}`,
    ""
  ];

  if (sessionRows.length) {
    lines.push("Рабочие учетные записи:");
    for (const row of sessionRows) {
      lines.push(`${row.user} | сервер=${row.server || "-"} | сессии=${row.session_human} | оболочка=${row.command_human || "0m"} | разработка=${row.coding_human || "0m"} | конфиги=${row.config_human || "0m"} | действий=${row.command_count || 0} | открыто=${row.open_human} | сессий=${row.session_count}/${row.open_sessions} | событий=${row.evidence_count} | источники=${row.source_summary || "-"} | первое=${formatDate(row.first_seen)} | последнее=${formatDate(row.last_seen)}`);
      if (Array.isArray(row.intervals) && row.intervals.length) {
        lines.push("  SSH-сессии:");
        for (const interval of row.intervals) {
          lines.push(`  - ${formatDate(interval.started_at)} -> ${formatDate(interval.ended_at)} | ${interval.duration_human}${interval.open ? " | открыта" : ""} | ${interval.source_summary || "-"}`);
        }
      }
      if (Array.isArray(row.command_windows) && row.command_windows.length) {
        lines.push("  Подтвержденные интервалы в оболочке:");
        for (const interval of row.command_windows) {
          lines.push(`  - ${formatDate(interval.started_at)} -> ${formatDate(interval.ended_at)} | ${interval.duration_human} | ${interval.source_summary || "-"}`);
        }
      }
      if (Array.isArray(row.coding_windows) && row.coding_windows.length) {
        lines.push("  Интервалы разработки:");
        for (const interval of row.coding_windows) {
          lines.push(`  - ${formatDate(interval.started_at)} -> ${formatDate(interval.ended_at)} | ${interval.duration_human} | ${interval.source_summary || "-"}`);
        }
      }
      if (Array.isArray(row.config_windows) && row.config_windows.length) {
        lines.push("  Интервалы работы с конфигами:");
        for (const interval of row.config_windows) {
          lines.push(`  - ${formatDate(interval.started_at)} -> ${formatDate(interval.ended_at)} | ${interval.duration_human} | ${interval.source_summary || "-"}`);
        }
      }
      if (Array.isArray(row.actions) && row.actions.length) {
        lines.push("  Подтвержденные действия:");
        for (const action of row.actions) {
          const pathText = Array.isArray(action.paths) && action.paths.length ? ` | пути=${action.paths.join("; ")}` : "";
          lines.push(`  - ${formatDate(action.at)} | ${describeLinuxAuditCategory(action.category)} | ${action.summary || "-"} | ${action.source || "-"}${pathText}`);
        }
      }
    }
    lines.push("");
  }

  if (evidenceRows.length) {
    lines.push("Служебные записи без рабочих сессий:");
    for (const row of evidenceRows) {
      lines.push(`${row.user} | сервер=${row.server || "-"} | событий=${row.evidence_count} | источники=${row.source_summary || "-"} | первое=${formatDate(row.first_seen)} | последнее=${formatDate(row.last_seen)}`);
    }
  }

  hrReportPreview.value = lines.join("\n");
  hrReportMeta.textContent = `${sessionRows.length} рабочих учетных записей, ${evidenceRows.length} служебных, ${payload.successful_hosts || 0}/${payload.scanned_servers || 0} серверов`;
  hrReportStatus.textContent = "Отчет по проверке Linux создан автоматически.";
  updateHRReportDownload(buildLinuxAuditHRReportCSV(rows, payload, period, effective));
}

function resetHRReport() {
  hrReportPreview.value = "";
  hrReportMeta.textContent = "Отчет появится после расчета или проверки Linux.";
  hrReportStatus.textContent = "Отчет еще не создан.";
  updateHRReportDownload("");
}

function buildHRReportCSV(rows, payload, period, effective) {
  const header = [
    "period",
    "interval",
    "employee",
    "server",
    "worked_human",
    "worked_minutes",
    "confirmed_human",
    "confirmed_minutes",
    "unconfirmed_human",
    "unconfirmed_minutes",
    "idle_human",
    "idle_minutes",
    "disconnected_human",
    "disconnected_minutes",
    "unknown_human",
    "unknown_minutes",
    "samples",
    "snapshots_total",
    "activity_windows_total"
  ];
  const lines = [header.join(",")];

  for (const row of rows) {
    lines.push([
      period,
      `${effective.start}-${effective.end}`,
      row.user,
      row.server || "",
      row.worked_human,
      row.worked_minutes,
      row.confirmed_human,
      row.confirmed_minutes,
      row.unconfirmed_human,
      row.unconfirmed_minutes,
      row.idle_human,
      row.idle_minutes,
      row.disconnected_human,
      row.disconnected_minutes,
      row.unknown_human,
      row.unknown_minutes,
      row.samples,
      payload.snapshots || 0,
      payload.windows || 0
    ].map(csvCell).join(","));
  }

  return lines.join("\n");
}

function buildLinuxAuditHRReportCSV(rows, payload, period, effective) {
  const header = [
    "report_type",
    "period",
    "interval",
    "server",
    "account",
    "has_sessions",
    "session_human",
    "session_minutes",
    "command_human",
    "command_minutes",
    "command_count",
    "coding_human",
    "coding_minutes",
    "coding_count",
    "config_human",
    "config_minutes",
    "config_count",
    "open_human",
    "open_minutes",
    "session_count",
    "open_sessions",
    "evidence_count",
    "sources",
    "first_seen",
    "last_seen",
    "interval_started_at",
    "interval_ended_at",
    "interval_duration_human",
    "interval_duration_minutes",
    "interval_open",
    "interval_sources",
    "hosts_scanned",
    "hosts_successful"
  ];
  const lines = [header.join(",")];

  for (const row of rows) {
    const intervals = Array.isArray(row.intervals) && row.intervals.length ? row.intervals : [null];
    for (const interval of intervals) {
      lines.push([
        "linux_audit",
        period,
        `${effective.start}-${effective.end}`,
        row.server || "",
        row.user || "",
        row.has_sessions ? "yes" : "no",
        row.session_human || "",
        row.session_minutes || 0,
        row.command_human || "",
        row.command_minutes || 0,
        row.command_count || 0,
        row.coding_human || "",
        row.coding_minutes || 0,
        row.coding_count || 0,
        row.config_human || "",
        row.config_minutes || 0,
        row.config_count || 0,
        row.open_human || "",
        row.open_minutes || 0,
        row.session_count || 0,
        row.open_sessions || 0,
        row.evidence_count || 0,
        row.source_summary || "",
        row.first_seen || "",
        row.last_seen || "",
        interval?.started_at || "",
        interval?.ended_at || "",
        interval?.duration_human || "",
        interval?.duration_minutes || 0,
        interval?.open ? "yes" : "no",
        interval?.source_summary || "",
        payload.scanned_servers || 0,
        payload.successful_hosts || 0
      ].map(csvCell).join(","));
    }
  }

  return lines.join("\n");
}

function updateHRReportDownload(csvText) {
  if (hrReportDownloadUrl) {
    URL.revokeObjectURL(hrReportDownloadUrl);
    hrReportDownloadUrl = "";
  }

  if (!csvText) {
    downloadHRReportButton.disabled = true;
    downloadHRReportButton.dataset.downloadUrl = "";
    downloadHRReportButton.dataset.filename = "";
    return;
  }

  hrReportDownloadUrl = URL.createObjectURL(new Blob([csvText], { type: "text/csv;charset=utf-8" }));
  downloadHRReportButton.disabled = false;
  downloadHRReportButton.dataset.downloadUrl = hrReportDownloadUrl;
  downloadHRReportButton.dataset.filename = buildHRReportFilename();
}

function downloadHRReport() {
  const url = downloadHRReportButton.dataset.downloadUrl;
  if (!url) {
    return;
  }
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = downloadHRReportButton.dataset.filename || buildHRReportFilename();
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
}

function buildHRReportFilename() {
  const since = (filterSinceDate.value || "since").replaceAll("-", "");
  const until = (filterUntilDate.value || "until").replaceAll("-", "");
  return `otchet-hr-${since}-${until}.csv`;
}

function csvCell(value) {
  const text = String(value ?? "");
  if (!text.includes(",") && !text.includes('"') && !text.includes("\n")) {
    return text;
  }
  return `"${text.replaceAll('"', '""')}"`;
}

function humanizeMinutes(minutes) {
  const safe = Number(minutes || 0);
  if (safe <= 0) {
    return "0m";
  }
  const hours = Math.floor(safe / 60);
  const remainder = safe % 60;
  if (hours === 0) {
    return `${remainder}m`;
  }
  if (remainder === 0) {
    return `${hours}h`;
  }
  return `${hours}h ${remainder}m`;
}

async function loadFileInto(event, target) {
  const [file] = event.target.files;
  if (!file) {
    return;
  }

  target.value = await file.text();
  statusLine.textContent = `${file.name} загружен.`;
}

async function loadLinuxServers() {
  try {
    const response = await fetch("/api/linux-servers");
    if (!response.ok) {
      throw new Error("Не удалось загрузить список Linux-серверов");
    }
    const payload = await response.json();
    linuxServers = payload.servers || [];
    renderLinuxServers();
    inventoryStatus.textContent = `Сохранено серверов: ${linuxServers.length}.`;
  } catch (error) {
    inventoryStatus.textContent = `Ошибка: ${error.message}`;
  }
}

function renderLinuxServers() {
  if (!linuxServers.length) {
    linuxServersBody.innerHTML = `<tr><td colspan="7" class="empty-state">Серверы еще не добавлены.</td></tr>`;
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
        <button class="ghost-button small-button" type="button" onclick="editLinuxServer('${escapeJs(server.id)}')">Изменить</button>
        <button class="ghost-button small-button danger-button" type="button" onclick="deleteLinuxServer('${escapeJs(server.id)}')">Удалить</button>
      </td>
    </tr>
  `).join("");
}

async function saveLinuxServer() {
  saveLinuxServerButton.disabled = true;
  inventoryStatus.textContent = "Сохраняю сервер...";

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
      throw new Error(await response.text() || "Не удалось сохранить сервер");
    }
    resetLinuxServerForm();
    await loadLinuxServers();
    inventoryStatus.textContent = "Сервер сохранен.";
  } catch (error) {
    inventoryStatus.textContent = `Ошибка: ${error.message}`;
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
  inventoryStatus.textContent = `Редактирование: ${server.name || server.host}.`;
}

async function deleteLinuxServer(id) {
  const server = linuxServers.find(item => item.id === id);
  if (!server) {
    return;
  }
  if (!window.confirm(`Удалить сервер ${server.name || server.host}?`)) {
    return;
  }
  try {
    const response = await fetch(`/api/linux-servers?id=${encodeURIComponent(id)}`, { method: "DELETE" });
    if (!response.ok) {
      throw new Error(await response.text() || "Не удалось удалить сервер");
    }
    await loadLinuxServers();
    inventoryStatus.textContent = "Сервер удален.";
  } catch (error) {
    inventoryStatus.textContent = `Ошибка: ${error.message}`;
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
    linuxAuditStatus.textContent = "Выберите хотя бы один сервер.";
    return;
  }

  runLinuxAuditButton.disabled = true;
  linuxAuditStatus.textContent = "Идет проверка серверов...";

  try {
    const response = await fetch("/api/linux-audit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        server_ids: selected,
        since_date: filterSinceDate.value,
        until_date: filterUntilDate.value,
        interval_start: effectiveInterval().start,
        interval_end: effectiveInterval().end
      })
    });
    if (!response.ok) {
      throw new Error(await response.text() || "Проверка Linux завершилась с ошибкой");
    }

    const payload = await response.json();
    renderLinuxAuditRows(payload.rows || []);
    renderBoxWarnings(linuxAuditWarnings, payload.warnings || []);
    linuxAuditMeta.textContent = `Проверено серверов: ${payload.successful_hosts}/${payload.scanned_servers}`;
    renderLinuxAuditHRReport(payload);
    linuxAuditStatus.textContent = "Проверка Linux завершена.";
  } catch (error) {
    linuxAuditStatus.textContent = `Ошибка: ${error.message}`;
    renderLinuxAuditRows([]);
    renderBoxWarnings(linuxAuditWarnings, []);
    resetHRReport();
    linuxAuditMeta.textContent = "Нет данных проверки.";
  } finally {
    runLinuxAuditButton.disabled = false;
  }
}

function renderLinuxAuditRows(rows) {
  if (!rows.length) {
    linuxAuditBody.innerHTML = `<tr><td colspan="14" class="empty-state">Нет строк по Linux-аудиту.</td></tr>`;
    return;
  }

  linuxAuditBody.innerHTML = rows.map(row => `
    <tr>
      <td>${escapeHtml(row.server)}</td>
      <td>${escapeHtml(row.user)}</td>
      <td>${escapeHtml(row.session_human)}</td>
      <td>${escapeHtml(row.command_human || "0m")}</td>
      <td>${escapeHtml(row.coding_human || "0m")} / ${escapeHtml(String(row.coding_count || 0))}</td>
      <td>${escapeHtml(row.config_human || "0m")} / ${escapeHtml(String(row.config_count || 0))}</td>
      <td>${escapeHtml(String(row.command_count || 0))}</td>
      <td>${escapeHtml(row.open_human)}</td>
      <td>${escapeHtml(String(row.session_count))} / ${escapeHtml(String(row.open_sessions))}</td>
      <td>${escapeHtml(String(row.evidence_count))}</td>
      <td>${escapeHtml(row.source_summary || "-")}</td>
      <td>${escapeHtml(formatDate(row.first_seen))}</td>
      <td>${escapeHtml(formatDate(row.last_seen))}</td>
      <td>${renderLinuxAuditTimeline(row)}</td>
    </tr>
  `).join("");
}

function renderLinuxAuditTimeline(row) {
  if (!row.has_sessions || !row.intervals || !row.intervals.length) {
    return `<span class="summary-meta">Есть только события. Рабочие интервалы не найдены.</span>`;
  }

  const sessionItems = row.intervals.map(interval => {
    const source = interval.source_summary ? `, источник: ${escapeHtml(interval.source_summary)}` : "";
    const openMark = interval.open ? " открыта" : "";
    return `<div>SSH: ${escapeHtml(formatDate(interval.started_at))} -> ${escapeHtml(formatDate(interval.ended_at))} (${escapeHtml(interval.duration_human)}${openMark})${source}</div>`;
  }).join("");
  const shellItems = Array.isArray(row.command_windows) && row.command_windows.length
    ? row.command_windows.map(interval => `<div>Оболочка: ${escapeHtml(formatDate(interval.started_at))} -> ${escapeHtml(formatDate(interval.ended_at))} (${escapeHtml(interval.duration_human)})${interval.source_summary ? `, источник: ${escapeHtml(interval.source_summary)}` : ""}</div>`).join("")
    : `<div class="summary-meta">Подтвержденные интервалы в оболочке не найдены.</div>`;
  const codingItems = Array.isArray(row.coding_windows) && row.coding_windows.length
    ? row.coding_windows.map(interval => `<div>Разработка: ${escapeHtml(formatDate(interval.started_at))} -> ${escapeHtml(formatDate(interval.ended_at))} (${escapeHtml(interval.duration_human)})${interval.source_summary ? `, источник: ${escapeHtml(interval.source_summary)}` : ""}</div>`).join("")
    : "";
  const configItems = Array.isArray(row.config_windows) && row.config_windows.length
    ? row.config_windows.map(interval => `<div>Конфиги: ${escapeHtml(formatDate(interval.started_at))} -> ${escapeHtml(formatDate(interval.ended_at))} (${escapeHtml(interval.duration_human)})${interval.source_summary ? `, источник: ${escapeHtml(interval.source_summary)}` : ""}</div>`).join("")
    : "";
  const actionItems = Array.isArray(row.actions) && row.actions.length
    ? row.actions.map(action => {
      const pathText = Array.isArray(action.paths) && action.paths.length ? `, пути: ${escapeHtml(action.paths.join(", "))}` : "";
      return `<div>Действие: ${escapeHtml(formatDate(action.at))} | ${escapeHtml(describeLinuxAuditCategory(action.category))} | ${escapeHtml(action.summary || "-")} | ${escapeHtml(action.source || "-")}${pathText}</div>`;
    }).join("")
    : `<div class="summary-meta">Подтвержденные действия не найдены.</div>`;

  return `
    <details>
      <summary>Сессии: ${escapeHtml(String(row.intervals.length))}, оболочка: ${escapeHtml(String((row.command_windows || []).length))}, действий: ${escapeHtml(String((row.actions || []).length))}</summary>
      ${sessionItems}
      ${shellItems}
      ${codingItems}
      ${configItems}
      ${actionItems}
    </details>
  `;
}

function describeLinuxAuditCategory(category) {
  switch (category) {
    case "coding":
      return "разработка";
    case "config":
      return "конфиги";
    default:
      return "оболочка";
  }
}

function renderBoxWarnings(element, warnings) {
  warnings = Array.isArray(warnings) ? warnings : [];
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
    methods.push("пароль");
  }
  if (server.private_key_pem) {
    methods.push("ключ");
  }
  return escapeHtml(methods.join(" + ") || "не указан");
}

function setDefaultDateRange() {
  const now = new Date();
  const before = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  filterUntilDate.value = toDateInput(now);
  filterSinceDate.value = toDateInput(before);
}

function toDateInput(date) {
  const pad = value => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
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

function persistDefaultIntervals() {
  window.localStorage.setItem(intervalStorageKey, JSON.stringify({
    start: defaultIntervalStart.value,
    end: defaultIntervalEnd.value
  }));
  updateEffectiveIntervalLabel();
}

function hydrateIntervalDefaults() {
  try {
    const saved = JSON.parse(window.localStorage.getItem(intervalStorageKey) || "{}");
    if (saved.start) {
      defaultIntervalStart.value = saved.start;
      operatorIntervalStart.value = saved.start;
    }
    if (saved.end) {
      defaultIntervalEnd.value = saved.end;
      operatorIntervalEnd.value = saved.end;
    }
  } catch (error) {
    console.error(error);
  }
}

function effectiveInterval() {
  if (useOperatorInterval.checked) {
    return {
      start: operatorIntervalStart.value,
      end: operatorIntervalEnd.value
    };
  }
  return {
    start: defaultIntervalStart.value,
    end: defaultIntervalEnd.value
  };
}

function updateEffectiveIntervalLabel() {
  const effective = effectiveInterval();
  intervalEffectiveLabel.textContent = useOperatorInterval.checked
    ? `Будет использован заданный вручную интервал: ${effective.start}-${effective.end}.`
    : `Будет использован интервал по умолчанию: ${effective.start}-${effective.end}.`;
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
