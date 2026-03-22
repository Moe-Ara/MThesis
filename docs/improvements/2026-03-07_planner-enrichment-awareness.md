# Improvement: Enrichment-Aware Planner Post-Processing

**Date:** 2026-03-07
**Status:** Deployed

---

## What Was Changed

The `CustomNNPlanner` in `intelligence/planners/custom_nn.py` now applies a rule-based
enrichment correction layer **after** MLP inference, using `alert.context.assetCriticality`,
`alert.context.privileged`, and `alert.context.environment` to override or augment the model's output.

---

## Why This Was Done

The MLP was trained on structured features extracted from alert type, severity, confidence,
and entity presence flags — it has no visibility into enrichment context.
Two alerts of the same type can produce identical model outputs even when one targets a
`criticality=5` production server and the other a dev workstation.

**Before**: A BruteForce alert on `web-server-prod` (crit=5, root account) produced:
- Strategy: `Contain`
- Actions: `BlockIp`, `Notify`
- Priority: ~65
- No `CollectForensics`

**After** (with enrichment post-processing):
- Strategy: `ContainAndCollect` (upgraded — crit=5 asset warrants forensic preservation)
- Actions: `BlockIp`, `CollectForensics`, `DisableUser` (root account targeted), `Notify`
- Priority: 85 (floored — crit=5 asset must be high priority)

This mirrors how a real SOC analyst escalates: *"Same brute-force pattern, but this is the
production web server with a root account — we collect forensics before we isolate."*

---

## Implementation

The correction layer runs inside `CustomNNPlanner.plan()` immediately after decoding
strategy, actions, and priority from the model. No retraining is needed.

### Strategy escalation rules
| Condition | Model output | Corrected to |
|-----------|-------------|--------------|
| crit≥5 + conf≥70% | ObserveMore / NotifyOnly | Contain |
| crit≥5 + conf≥70% | Contain | ContainAndCollect |
| crit≥4 + conf≥70% | ObserveMore | Contain |
| privileged + conf≥65% | ObserveMore | Contain |

### Forced action additions
| Condition | Action added |
|-----------|-------------|
| crit≥4 + conf≥65% | `CollectForensics` (evidence preservation) |
| privileged + BruteForce + conf≥70% + username present | `DisableUser` + `EnableUser` rollback |

### Priority floors
| Asset criticality | Priority floor |
|-------------------|---------------|
| 5 (critical) | 85 |
| 4 (high) | 70 |
| 3 (medium) | 55 |

Floors use `max()` so they only apply when the model prediction is below the threshold.

---

## Evidence in Rationale

Enrichment overrides are appended to the plan's `rationale` list so they are visible
in the C# `PrintDemoSummary()` output and in any audit logs. Example:

```
"Strategy upgraded to ContainAndCollect — critical asset requires forensic preservation."
"CollectForensics added — asset criticality=5/5 warrants evidence preservation."
"DisableUser added — privileged account targeted by brute-force attack."
"Priority floored to 85 — asset criticality=5/5."
```

---

## Expected Results for Demo Alerts

| Alert | Before | After |
|-------|--------|-------|
| BruteForce on web-server-prod (crit=5, root) | Contain / priority≈65 | **ContainAndCollect** / priority=85 / +CollectForensics / +DisableUser |
| Malware on finance-laptop-07 (crit=4) | Contain / priority≈70 | Contain / priority=70 / **+CollectForensics** |
| PowerShell on hr-workstation-12 (crit=3) | Contain / priority≈60 | Contain / priority=60 (no change — crit=3 below threshold) |

---

## How Context Flows

```
RawAlert (Wazuh webhook)
    → NormalizationPipeline (enrichment lookup)
    → EnrichedAlert.Context.Asset.Criticality = 5
    → HttpPlannerClient sends alert dict with context.assetCriticality=5, context.privileged=true
    → Python /v1/plan endpoint receives alert dict
    → CustomNNPlanner.plan():
        1. MLP inference → strategy=Contain, actions=[BlockIp, Notify], priority=65
        2. Enrichment post-processing:
           - crit=5 + conf=0.85 → strategy=ContainAndCollect
           - crit=5 → CollectForensics added
           - privileged + BruteForce → DisableUser added
           - crit=5 → priority floored to 85
    → Returns: strategy=ContainAndCollect, priority=85, 4 actions
```

---

## Files Changed

| File | Change |
|------|--------|
| `intelligence/planners/custom_nn.py` | Added enrichment post-processing block in `plan()` after action decoding |
