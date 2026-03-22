function setSeverityDisplay() {
    const slider = document.getElementById("severity-override");
    const output = document.getElementById("severity-value");
    if (!slider || !output) {
        return;
    }
    output.textContent = Number(slider.value).toFixed(1);
    slider.addEventListener("input", () => {
        output.textContent = Number(slider.value).toFixed(1);
    });
}

async function submitFeedback(incidentId, verdict) {
    const slider = document.getElementById("severity-override");
    const severity = slider ? Number(slider.value) : 1.0;
    const resultBox = document.getElementById("feedback-result");

    const response = await fetch(`/api/incidents/${incidentId}/feedback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ verdict: verdict, severity_override: severity, analyst: "analyst" }),
    });

    if (!response.ok) {
        if (resultBox) {
            resultBox.textContent = "Feedback failed."
        }
        return;
    }

    const payload = await response.json();
    const riskValue = document.getElementById("risk-score-value");
    const scorePill = document.getElementById("risk-score");
    const evidenceValue = document.getElementById("evidence-score");
    const confidenceValue = document.getElementById("confidence");

    if (riskValue) {
        riskValue.textContent = payload.after.risk_score.toFixed(1);
    }
    if (scorePill) {
        scorePill.setAttribute("data-score", payload.after.risk_score.toFixed(1));
    }
    if (evidenceValue) {
        evidenceValue.textContent = payload.after.evidence_score_raw.toFixed(2);
    }
    if (confidenceValue) {
        confidenceValue.textContent = (payload.after.confidence * 100).toFixed(1) + "%";
    }

    applyScoreColors();

    if (resultBox) {
        const changes = payload.weight_diff.changes || [];
        if (changes.length === 0) {
            resultBox.textContent = "Feedback recorded. No weight change needed.";
        } else {
            const lines = changes.map((change) => `${change.feature}: ${change.delta > 0 ? "+" : ""}${change.delta}`);
            resultBox.textContent = `Feedback recorded. Weight updates: ${lines.join(", ")}`;
        }
    }
}

async function logTrace(incidentId, action) {
    const response = await fetch(`/api/incidents/${incidentId}/trace`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: action, analyst: "analyst" }),
    });

    if (!response.ok) {
        return;
    }

    const payload = await response.json();
    const recommendations = document.getElementById("recommendations");
    const lastAction = document.getElementById("last-action");
    if (lastAction) {
        lastAction.textContent = action.replace(/_/g, " ");
    }

    if (recommendations) {
        if (!payload.recommendations || payload.recommendations.length === 0) {
            recommendations.innerHTML = "<div class=\"muted\">No recommendations yet.</div>";
            return;
        }
        recommendations.innerHTML = payload.recommendations
            .map(
                (rec) =>
                    `<button class="chip" onclick="logTrace('${incidentId}', '${rec.action}')">${rec.action.replace(/_/g, " ")} <span>${rec.count}</span></button>`
            )
            .join("");
    }
}

document.addEventListener("DOMContentLoaded", () => {
    setSeverityDisplay();
    applyScoreColors();
});

function applyScoreColors() {
    document.querySelectorAll(".score-pill").forEach((pill) => {
        const score = Number(pill.getAttribute("data-score")) || 0;
        pill.classList.remove("high", "medium", "low");
        if (score >= 70) {
            pill.classList.add("high");
        } else if (score >= 40) {
            pill.classList.add("medium");
        } else {
            pill.classList.add("low");
        }
    });
}


