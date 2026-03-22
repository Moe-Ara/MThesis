# Improvement: Threat Intelligence in Hypothesis & Scoring

**Date:** 2026-03-07
**Status:** Deployed

---

## What Was Changed

1. **`HttpThreatScorerClient.cs`**: Extended the `context` block sent to the Python scorer
   to include `tiReputationScore` (int) and `tiTags` (string array) from the enriched alert's
   `ThreatIntelContext`.

2. **`intelligence/scorers/classifier.py`**:
   - `_build_hypothesis()`: Generates a TI narrative sentence when reputation ≥ 50
   - `_build_evidence()`: Appends `ti_reputation=X/100` and `ti_tags=[...]` to the evidence list
   - `score()`: Applies TI confidence/severity boosts (TI≥90 → conf≥90%, TI≥70 → conf≥82%)

---

## Why This Was Done

The previous hypothesis text described *what happened* based on alert type and entities,
but said nothing about *why the system is confident* in its assessment.

A real SOC analyst would say: *"This brute-force from 185.220.101.47 stands out because
that IP is a known TOR exit node with a 95/100 threat reputation — it's not a false positive."*

The hypothesis now includes this reasoning, making the system's explanation credible and
specific to the actual threat intelligence data.

---

## TI Boost Thresholds

| TI reputation score | Confidence floor | Severity floor |
|--------------------|-----------------|----------------|
| ≥ 90 | 90% | 85 |
| ≥ 70 | 82% | 75 |
| ≥ 50 | 70% | (none) |

These boost the classifier's base output using `max()` so they only apply when the
raw classifier score is below the threshold.

---

## Example Hypothesis Output

**Before:**
> "Multiple failed authentication attempts against account 'root' (87 failed attempts) suggest brute-force activity. High likelihood of malicious intent. — Target is a critical production asset; compromised account has elevated privileges."

**After:**
> "Multiple failed authentication attempts against account 'root' (87 failed attempts) suggest brute-force activity. Origin identified in threat intelligence (tor-exit-node, brute-force, credential-stuffing; reputation 95/100). High likelihood of malicious intent. — Target is a critical production asset; compromised account has elevated privileges."

---

## Expected Results for Demo Alerts

| Alert | Before | After |
|-------|--------|-------|
| BruteForce on web-server-prod (TI=95, crit=5, root) | conf=85%, sev=80 | **conf=90%, sev=85** (TI≥90 boost) |
| Malware on finance-laptop-07 (TI=100 hash, crit=4) | conf=78%, sev=75 | **conf=90%, sev=85** (TI=100 boost) |
| PowerShell on hr-workstation-12 (no TI, crit=3) | conf=72%, sev=71 | conf=72%, sev=71 (unchanged) |

The malware alert now reaches 90% confidence because the file hash has a perfect 100/100
threat intelligence score — it's definitively known malware.

---

## How Context Flows

```
ThreatIntelEnricher matches srcIp=185.220.101.47 → reputation=95, tags=[tor-exit-node, ...]
    → enriched.Context.ThreatIntel = ThreatIntelContext(ReputationScore=95, Matches=[...])
    → HttpThreatScorerClient sends context.tiReputationScore=95, context.tiTags=[...]
    → ClassifierScorer.score(): ti_reputation=95 → confidence=max(conf, 0.90), severity=max(sev, 85)
    → _build_hypothesis(): "Origin identified in threat intelligence (tor-exit-node, ...)"
    → _build_evidence(): "ti_reputation=95/100", "ti_tags=[tor-exit-node, brute-force, credential-stuffing]"
```

---

## Files Changed

| File | Change |
|------|--------|
| `NetCore/Core/Scoring/HttpThreatScorerClient.cs` | Added `tiReputationScore` and `tiTags` to scorer context payload |
| `intelligence/scorers/classifier.py` | TI boost in `score()`, TI narrative in `_build_hypothesis()`, TI fields in `_build_evidence()` |
