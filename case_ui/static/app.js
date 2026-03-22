const qs = (id) => document.getElementById(id);

let currentCases = [];
let activeCaseId = null;

const statusClass = (status) => {
  if (!status) return "neutral";
  const key = status.toLowerCase();
  if (key === "open") return "open";
  if (key === "inprogress") return "inprogress";
  if (key === "closed") return "closed";
  if (key === "falsepositive") return "falsepositive";
  return "neutral";
};

const badgeClass = (status) => {
  const key = statusClass(status);
  if (key === "closed") return "good";
  if (key === "open" || key === "inprogress") return "warn";
  if (key === "falsepositive") return "neutral";
  return "neutral";
};

const fmtDate = (value) => {
  if (!value) return "--";
  return new Date(value).toLocaleString();
};

const setText = (id, value) => {
  const el = qs(id);
  if (el) el.textContent = value ?? "--";
};

const renderStats = (stats) => {
  setText("statTotal", stats.Total ?? 0);
  setText("statOpen", stats.Open ?? 0);
  setText("statInProgress", stats.InProgress ?? 0);
  setText("statClosed", stats.Closed ?? 0);
  setText("statFalsePositive", stats.FalsePositive ?? 0);
};

const renderCases = (cases) => {
  const list = qs("caseList");
  const empty = qs("caseEmpty");
  list.innerHTML = "";

  if (!cases || cases.length === 0) {
    empty.style.display = "block";
    return;
  }

  empty.style.display = "none";
  cases.forEach((item) => {
    const row = document.createElement("div");
    row.className = `table-row ${item.CaseId === activeCaseId ? "active" : ""}`;
    row.dataset.caseId = item.CaseId;
    const status = item.Status || "Unknown";
    row.innerHTML = `
      <span class="mono">${item.CaseId.slice(0, 8)}...</span>
      <span class="status ${statusClass(status)}">${status}</span>
      <span>${item.Severity ?? "--"}</span>
      <span>${fmtDate(item.UpdatedAtUtc)}</span>
    `;
    row.addEventListener("click", () => selectCase(item.CaseId));
    list.appendChild(row);
  });
};

const renderCaseDetail = (data) => {
  if (!data || !data.case) {
    setText("caseId", "--");
    setText("caseSummary", "--");
    return;
  }

  const c = data.case;
  activeCaseId = c.CaseId;
  const badge = qs("caseStatusBadge");
  badge.textContent = c.Status || "--";
  badge.className = `badge ${badgeClass(c.Status)}`;

  setText("caseId", c.CaseId);
  setText("caseCorrelation", c.CorrelationId || "--");
  setText("caseAlertKey", c.AlertKey || "--");
  setText("caseSeverity", c.Severity || "--");
  setText("caseCreated", fmtDate(c.CreatedAtUtc));
  setText("caseUpdated", fmtDate(c.UpdatedAtUtc));
  setText("caseSummary", c.Summary || "--");

  const events = data.events || [];
  setText("eventCount", `${events.length} events`);
  const list = qs("eventList");
  list.innerHTML = "";
  if (events.length === 0) {
    list.innerHTML = `<div class="event-card"><div class="event-meta">No events recorded</div></div>`;
    return;
  }

  events.forEach((evt) => {
    const card = document.createElement("div");
    card.className = "event-card";
    const dataJson = evt.data ? JSON.stringify(evt.data, null, 2) : "--";
    card.innerHTML = `
      <h4>${evt.Type || "Event"}</h4>
      <div class="event-meta">${fmtDate(evt.TimestampUtc)} · ${evt.Message || ""}</div>
      <pre class="event-data">${dataJson}</pre>
    `;
    list.appendChild(card);
  });
};

const selectCase = async (caseId) => {
  activeCaseId = caseId;
  renderCases(currentCases);
  try {
    const res = await fetch(`/api/cases/${caseId}`);
    const data = await res.json();
    renderCaseDetail(data);
  } catch {
    renderCaseDetail(null);
  }
};

const loadStats = async () => {
  try {
    const res = await fetch("/api/stats");
    const data = await res.json();
    if (data.ok) {
      renderStats(data.stats || {});
    }
  } catch {
    renderStats({});
  }
};

const loadCases = async () => {
  try {
    const res = await fetch("/api/cases");
    const data = await res.json();
    if (data.ok) {
      currentCases = data.cases || [];
      renderCases(currentCases);
      if (currentCases.length > 0 && !activeCaseId) {
        selectCase(currentCases[0].CaseId);
      } else if (currentCases.length > 0) {
        selectCase(activeCaseId);
      }
    } else {
      currentCases = [];
      renderCases([]);
    }
  } catch {
    currentCases = [];
    renderCases([]);
  }
};

const refreshAll = async () => {
  await loadStats();
  await loadCases();
  setText("lastUpdated", new Date().toLocaleString());
};

qs("refreshBtn").addEventListener("click", refreshAll);

refreshAll();
setInterval(refreshAll, 8000);
