# Improvement: Enrichment-Boosted Threat Scoring

**Date:** 2026-03-07
**Status:** Deployed and verified

---

## What Was Changed

The `ClassifierScorer` in `intelligence/scorers/classifier.py` now uses the enrichment context passed from the C# engine (`context.assetCriticality`, `context.privileged`, `context.environment`) to:

1. **Boost confidence** when external enrichment corroborates the alert
2. **Escalate severity** for high-criticality assets in production
3. **Enrich the hypothesis text** with asset/identity context
4. **Include enrichment signals in evidence** list

---

## Why This Was Done

The ML classifier scores alerts based on text features (alert type, rule name, entities). However, two alerts of the same type — one on a dev workstation, one on a critical production server — should not produce the same confidence score.

**Before**: All alerts of the same type produced the same confidence floor (e.g., 72% for "high" label). The classifier had no visibility into whether the target was a critical asset.

**After**: The system reason-chains over enrichment:
- An alert on a **criticality-5 production asset** → confidence ≥ 85%, severity ≥ 80
- An alert on a **criticality-4 high-value asset** → confidence ≥ 78%, severity ≥ 70
- A **privileged identity** involved → confidence ≥ 75%
- All three can stack if multiple conditions apply

This is analogous to how a real SOC analyst would escalate: "Same alert, but this one is on a finance server with root — that changes the priority."

---

## Implementation

```python
# Apply enrichment boosts in ClassifierScorer.score()
asset_criticality = int(context.get("assetCriticality") or 0)
privileged = bool(context.get("privileged") or False)
environment = str(context.get("environment") or "")

if asset_criticality >= 5:
    confidence = max(confidence, 0.85)   # critical asset
    severity = max(severity, 80.0)
elif asset_criticality >= 4:
    confidence = max(confidence, 0.78)   # high-criticality asset
    severity = max(severity, 70.0)

if privileged:
    confidence = max(confidence, 0.75)   # privileged identity

if asset_criticality >= 4 and environment.lower() == "prod":
    severity = max(severity, 75.0)       # prod escalation
```

The boosts use `max()` so they only apply when the base classifier output is below the threshold — they **floor** the confidence rather than override it, preserving cases where the model is already more decisive.

---

## Evidence & Hypothesis Enrichment

The evidence list now includes:
```
asset_criticality=5/5 (critical)
target_identity=privileged
```

The hypothesis now appends enrichment context:
```
"Multiple failed authentication attempts against account 'root' suggest brute-force activity.
 High likelihood of malicious intent. — Target is a critical production asset;
 compromised account has elevated privileges."
```

---

## Verified Results

| Alert | Before | After |
|-------|--------|-------|
| BruteForce on web-server-prod (crit=5, root user) | conf=72%, sev=71 | **conf=85%, sev=80** |
| Malware on finance-laptop-07 (crit=4) | conf=72%, sev=71 | **conf=78%, sev=75** |
| PowerShell on hr-workstation-12 (crit=3) | conf=72%, sev=71 | conf=72%, sev=71 (unchanged) |

The confidence difference between a critical and medium-criticality alert is now **13 percentage points**, which translates to a meaningful difference in plan priority (88 vs 80).

---

## How Context Flows

```
RawAlert (Wazuh webhook)
    → NormalizationPipeline (normalization + enrichment)
    → EnrichedAlert.Context.Asset.Criticality = 5
    → HttpThreatScorerClient sends: context.assetCriticality=5, context.privileged=True
    → Python /v1/score endpoint receives alert dict with context nested
    → ClassifierScorer.score() applies enrichment boosts
    → Returns: confidence=0.85, severity=80
    → PolicyEngine uses higher confidence to justify auto-executing BlockIp
```

---

## Files Changed

| File | Change |
|------|--------|
| `intelligence/scorers/classifier.py` | Added enrichment boost logic in `score()`, enrichment notes in `_build_hypothesis()`, and enrichment fields in `_build_evidence()` |
