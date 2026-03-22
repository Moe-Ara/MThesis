const qs = (id) => document.getElementById(id);

const STRATEGY_MAP = [
  "ObserveMore",
  "NotifyOnly",
  "Contain",
  "ContainAndCollect",
  "EscalateToHuman",
];

const ACTION_MAP = [
  "BlockIp",
  "UnblockIp",
  "IsolateHost",
  "UnisolateHost",
  "DisableUser",
  "EnableUser",
  "KillProcess",
  "QuarantineFile",
  "OpenTicket",
  "Notify",
  "CollectForensics",
];

const POLICY_STATUS_MAP = ["Approved", "PendingApproval", "Denied"];
const EXEC_STATUS_MAP = ["Skipped", "DryRun", "Succeeded", "Failed"];

const stagePill = (stage) => {
  if (!stage) return ["neutral", "Waiting"];
  if (stage.includes("Failed")) return ["bad", stage];
  if (stage === "Completed") return ["good", stage];
  return ["warn", stage];
};

const toFixed = (val, digits = 2) => {
  if (val === null || val === undefined || Number.isNaN(val)) return "--";
  return Number(val).toFixed(digits);
};

const setText = (id, value) => {
  const el = qs(id);
  if (el) el.textContent = value ?? "--";
};

const setChips = (id, items, tone = "chip") => {
  const el = qs(id);
  if (!el) return;
  el.innerHTML = "";
  if (!items || items.length === 0) {
    el.innerHTML = `<span class="chip">--</span>`;
    return;
  }
  items.forEach((item) => {
    const span = document.createElement("span");
    span.className = `${tone}`;
    span.textContent = item;
    el.appendChild(span);
  });
};

const setList = (id, items, formatter) => {
  const el = qs(id);
  if (!el) return;
  el.innerHTML = "";
  if (!items || items.length === 0) {
    el.innerHTML = `<div class="reason-item"><span>--</span><span>--</span></div>`;
    return;
  }
  items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "reason-item";
    row.innerHTML = formatter(item);
    el.appendChild(row);
  });
};

const normalize = (trace) => {
  const assessment = trace.assessment || {};
  const plan = trace.plan || {};
  const policy = trace.policy || {};
  const execution = trace.execution || {};
  const raw = trace.rawAlert || {};
  const enriched = trace.enriched || {};
  return { assessment, plan, policy, execution, raw, enriched };
};

const updatePipeline = (stage) => {
  const steps = ["Ingest", "Normalize", "Score", "Plan", "Policy", "Execute"];
  steps.forEach((step) => {
    const el = document.querySelector(`.step[data-step="${step}"]`);
    if (!el) return;
    el.classList.remove("active", "fail");
  });

  if (!stage) return;

  if (stage.includes("Normalization")) {
    setActive("Normalize", true);
  } else if (stage.includes("Planning")) {
    setActive("Plan", true);
  } else if (stage.includes("Policy")) {
    setActive("Policy", true);
  } else if (stage.includes("Execution")) {
    setActive("Execute", true);
  } else if (stage === "Completed") {
    steps.forEach((s) => setActive(s, false));
  }
};

const setActive = (step, fail) => {
  const el = document.querySelector(`.step[data-step="${step}"]`);
  if (!el) return;
  el.classList.add(fail ? "fail" : "active");
};

const renderPolicyDecisions = (policy) => {
  const perAction = policy.perAction || [];
  const decisionsEl = qs("policyDecisions");
  decisionsEl.innerHTML = "";
  if (perAction.length === 0) {
    decisionsEl.innerHTML = `<div class="exec-item"><div class="exec-header">No policy decisions</div></div>`;
    return;
  }
  perAction.forEach((item) => {
    const actionType =
      typeof item.action?.type === "number" ? ACTION_MAP[item.action.type] : item.action?.type;
    const status =
      typeof item.status === "number" ? POLICY_STATUS_MAP[item.status] : item.status;
    const reasons = (item.reasons || []).join(" | ");
    const row = document.createElement("div");
    row.className = "exec-item";
    row.innerHTML = `
      <div class="exec-header">
        <span>${actionType || "Action"}</span>
        <span>${status || "Unknown"}</span>
      </div>
      <div class="exec-meta">${reasons || "--"}</div>
    `;
    decisionsEl.appendChild(row);
  });
};

const renderExecution = (execution) => {
  const execActions = execution.actions || [];
  const execList = qs("executionActions");
  execList.innerHTML = "";
  if (execActions.length === 0) {
    execList.innerHTML = `<div class="exec-item"><div class="exec-header">No execution actions</div></div>`;
  } else {
    execActions.forEach((act) => {
      const statusText =
        typeof act.status === "number" ? EXEC_STATUS_MAP[act.status] : act.status;
      const typeText =
        typeof act.type === "number" ? ACTION_MAP[act.type] : act.type;
      const item = document.createElement("div");
      item.className = "exec-item";
      item.innerHTML = `
        <div class="exec-header">
          <span>${typeText}</span>
          <span>${statusText || "Unknown"}</span>
        </div>
        <div class="exec-meta">${act.message || ""}</div>
      `;
      execList.appendChild(item);
    });
  }
  const execSummary = execActions.length
    ? `${execActions.length} actions`
    : "No actions";
  setText("executionSummary", execSummary);
};

const renderAudit = (trace) => {
  const auditEntries = trace.auditEntries || [];
  if (auditEntries.length === 0) {
    setText("auditLog", "No audit entries found.");
    return;
  }
  const auditText = auditEntries
    .map((entry) => {
      const ts = entry.timestampUtc || "";
      const component = entry.component || "";
      const type = entry.eventType || "";
      const msg = entry.message || "";
      return `${ts} ${component}.${type} - ${msg}`;
    })
    .join("\n");
  setText("auditLog", auditText);
};

const renderReasoning = (reasoning) => {
  setText("evidenceScore", toFixed(reasoning?.evidence_score_raw ?? "--", 2));
  setText("contextMultiplier", toFixed(reasoning?.context_multiplier ?? "--", 2));
  setText("riskScore", toFixed(reasoning?.risk_score ?? "--", 2));
  setText("confidence", toFixed(reasoning?.confidence ?? "--", 2));
  const version = reasoning?.weights_version ?? "--";
  setText("weightsVersion", `weights v${version}`);

  setList("topReasons", reasoning?.top_reasons || [], (item) => {
    return `<strong>${item.feature}</strong><span>${item.contribution}</span>`;
  });
  const breakdownItems = Object.entries(reasoning?.context_breakdown || {}).map(
    ([key, value]) => ({ key, value })
  );
  setList("contextBreakdown", breakdownItems, (item) => {
    return `<strong>${item.key}</strong><span>${item.value}</span>`;
  });
};

const renderDiff = (diffs) => {
  const list = qs("weightDiff");
  list.innerHTML = "";
  if (!diffs || diffs.length === 0) {
    list.innerHTML = `<div class="diff-item"><span>No updates yet</span><span>--</span></div>`;
    return;
  }
  const latest = diffs[0];
  const changes = latest.changes || [];
  if (changes.length === 0) {
    list.innerHTML = `<div class="diff-item"><span>No weight change</span><span>--</span></div>`;
    return;
  }
  changes.slice(0, 6).forEach((change) => {
    const row = document.createElement("div");
    row.className = "diff-item";
    row.innerHTML = `<strong>${change.feature}</strong><span>${change.delta}</span>`;
    list.appendChild(row);
  });
};

const renderRecommendations = (rec) => {
  setText("lastAction", rec?.last_action || "--");
  setList("recommendations", rec?.items || [], (item) => {
    return `<strong>${item.action}</strong><span>${item.count}</span>`;
  });
};

const updateUI = (payload) => {
  if (!payload || payload.ok === false) {
    qs("traceStatus").textContent = payload?.message || "No trace yet";
    qs("traceStatus").className = "pill warn";
    return;
  }

  const trace = payload.trace;
  const { assessment, plan, policy, execution, raw, enriched } = normalize(trace);
  const severity = assessment.severity ?? enriched?.base?.severity ?? raw?.originalSeverity;

  const [pillClass, pillText] = stagePill(trace.stage);
  const stageEl = qs("stage");
  stageEl.textContent = pillText;
  stageEl.className = `pill ${pillClass}`;

  qs("traceStatus").textContent = "Active";
  qs("traceStatus").className = "pill good";

  setText("correlationId", trace.correlationId ?? "--");
  setText("lastUpdated", new Date(trace.timestampUtc || Date.now()).toLocaleString());

  setText("severity", severity ?? "--");
  const strategy =
    typeof plan.strategy === "number" ? STRATEGY_MAP[plan.strategy] : plan.strategy;
  setText("strategy", strategy ?? "--");

  setText("alertSummary", `${raw.alertType || raw.ruleName || "Alert"} | ${raw.alertId || "--"}`);
  setText("entities", JSON.stringify(enriched?.base?.entities || {}, null, 2));
  setText("hypothesis", assessment.hypothesis || "--");
  setText("evidence", (assessment.evidence || []).join(" | ") || "--");

  const actions = (plan.actions || [])
    .map((a) => {
      if (!a) return "";
      const typeName = typeof a.type === "number" ? ACTION_MAP[a.type] : a.type;
      const params = a.parameters ? JSON.stringify(a.parameters) : "";
      return `${typeName}${params ? " " + params : ""}`;
    })
    .filter(Boolean);
  const rollbacks = (plan.rollbackActions || [])
    .map((a) => (typeof a.type === "number" ? ACTION_MAP[a.type] : a.type))
    .filter(Boolean);
  const rationale = (plan.rationale || []).join(" | ") || "No rationale provided by planner.";
  const rawPlanner = plan.tags?.planner_raw;
  const rawReasoning = plan.tags?.planner_reasoning;

  setText("priority", plan.priority ?? "--");
  setChips("actions", actions, "chip good");
  setChips("rollbacks", rollbacks, "chip");
  setText("rationale", rationale);

  setChips(
    "approved",
    (policy.approved || []).map((a) => (typeof a.type === "number" ? ACTION_MAP[a.type] : a.type)),
    "chip good"
  );
  setChips(
    "pending",
    (policy.pendingApproval || []).map((a) => (typeof a.type === "number" ? ACTION_MAP[a.type] : a.type)),
    "chip warn"
  );
  setChips(
    "denied",
    (policy.denied || []).map((a) => (typeof a.type === "number" ? ACTION_MAP[a.type] : a.type)),
    "chip bad"
  );
  setText("policyNotes", (policy.notes || []).join(" | ") || "--");
  renderPolicyDecisions(policy);
  renderExecution(execution);
  renderAudit(trace);

  const rawJson = JSON.stringify(raw || {}, null, 2);
  const normalizedJson = JSON.stringify(enriched || {}, null, 2);
  setText("rawAlertJson", rawJson || "--");
  setText("normalizedAlertJson", normalizedJson || "--");

  let plannerPretty = null;
  if (rawPlanner) {
    try {
      const parsed = JSON.parse(rawPlanner);
      plannerPretty = JSON.stringify(parsed, null, 2);
    } catch {
      plannerPretty = rawPlanner;
    }
  }
  if (!plannerPretty) {
    plannerPretty = JSON.stringify(plan || {}, null, 2);
  }
  setText("plannerRawJson", plannerPretty);

  let reasoningPretty = null;
  if (rawReasoning) {
    try {
      const parsed = JSON.parse(rawReasoning);
      reasoningPretty = JSON.stringify(parsed, null, 2);
    } catch {
      reasoningPretty = rawReasoning;
    }
  }
  if (!reasoningPretty) {
    reasoningPretty = JSON.stringify(
      {
        summary: assessment.hypothesis || "",
        evidence: assessment.evidence || [],
        constraints: [],
        action_justifications: {},
      },
      null,
      2
    );
  }
  setText("plannerReasoningJson", reasoningPretty);

  renderReasoning(payload.reasoning);
  renderDiff(payload.feedback?.diffs || []);
  renderRecommendations(payload.recommendations);

  const model = payload.model || {};
  setText("scorerModel", `scorer: ${model.scorer_profile || "--"}`);
  setText("plannerModel", `planner: ${model.planner_profile || "--"}`);

  updatePipeline(trace.stage);
};

const loadConsole = async () => {
  try {
    const res = await fetch("/api/console");
    const data = await res.json();
    updateUI(data);
  } catch {
    updateUI({ ok: false, message: "Failed to fetch trace" });
  }
};

const sendFeedback = async (verdict) => {
  const severityOverride = Number(qs("severityOverride").value || 1.0);
  await fetch("/api/feedback", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      verdict,
      severity_override: severityOverride,
      analyst: "demo-analyst",
    }),
  });
  await loadConsole();
};

const sendTraceAction = async (action) => {
  await fetch("/api/trace-action", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action, analyst: "demo-analyst" }),
  });
  await loadConsole();
};

document.querySelectorAll(".feedback-actions button").forEach((btn) => {
  btn.addEventListener("click", () => sendFeedback(btn.dataset.verdict));
});

qs("severityOverride").addEventListener("input", (event) => {
  qs("severityOverrideValue").textContent = event.target.value;
});

document.querySelectorAll(".action-chip").forEach((chip) => {
  chip.addEventListener("click", () => sendTraceAction(chip.dataset.action));
});

loadConsole();
setInterval(loadConsole, 5000);
