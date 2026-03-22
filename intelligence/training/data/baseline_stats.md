# Baseline Stats — Before Fine-Tuning

**Model:** baron-security (Ollama)
**Date:** 2026-02-22
**Test:** 6 diverse alerts sent to intelligence service (scorer + planner)

## Scorer Results

| Alert ID | Alert Type | Severity | Confidence | Hypothesis |
|---|---|---|---|---|
| b-001 | PortScanFromIp | 0 | 0 | No malicious activity detected |
| b-002 | BruteForceUser | 0 | 0 | No malicious activity detected |
| b-003 | MalwareHashOnHost | 0 | 0 | No malicious activity detected |
| b-004 | SuspiciousProcessOnHost | 0 | 0 | No malicious activity detected |
| b-005 | BenignNoise | 0 | 0 | No malicious activity detected |
| b-006 | PortScanFromIp | 0 | 0 | No malicious activity detected |

- **Average severity:** 0.0
- **Average confidence:** 0.0
- **Evidence provided:** None for any alert
- **Threat discrimination:** None — all alerts scored identically regardless of type

## Planner Results

| Alert ID | Alert Type | Strategy | Actions | Priority |
|---|---|---|---|---|
| b-001 | PortScanFromIp | (empty) | [] | - |
| b-002 | BruteForceUser | NotifyOnly | OpenTicket, Notify | 50 |
| b-003 | MalwareHashOnHost | NotifyOnly | OpenTicket, Notify | 50 |
| b-004 | SuspiciousProcessOnHost | (empty) | [] | - |
| b-005 | BenignNoise | (empty) | [] | - |
| b-006 | PortScanFromIp | (empty) | [] | - |

- **Strategies used:** NotifyOnly (when any plan was generated)
- **Actions used:** OpenTicket, Notify only
- **Actions never used:** BlockIp, IsolateHost, DisableUser, KillProcess, QuarantineFile
- **Schema compliance:** Poor — planner wraps response in nested `"plan"` key instead of top-level fields

## Orchestrator Simulation Results

| Metric | Value |
|---|---|
| Total alerts pulled | 6 |
| Normalization failed | 3 (50%) — all EdgeMalformedAlert (expected, no entities) |
| Successfully processed | 3 |
| Actions approved | 2 per alert (OpenTicket + Notify) |
| Actions pending | 0 |
| Actions denied | 0 |
| Containment actions | 0 |

## Key Observations

1. **Scorer is completely non-functional** — returns severity=0, confidence=0 for every alert including obvious malware and brute force attacks. No threat discrimination at all.
2. **Planner defaults to passive responses** — only ever suggests OpenTicket and Notify. Never proposes containment actions (BlockIp, IsolateHost, etc.) even for clear threats.
3. **No evidence or reasoning** — scorer provides no evidence arrays, planner rationale is generic "low confidence" boilerplate.
4. **Wrong response schema** — planner nests output under a `"plan"` key instead of returning fields at the top level.
5. **Identical treatment** — benign noise and critical malware get the exact same response.

## Expected Post-Training Improvements

- Severity scores that correlate with actual threat level (malware > port scan > benign)
- Confidence values reflecting assessment certainty
- Meaningful hypotheses and evidence for each alert
- Strategy selection matching threat severity (Contain for malware, ObserveMore for benign)
- Appropriate containment actions (BlockIp for scanning IPs, QuarantineFile for malware)
- Correct top-level JSON schema without nested wrapping
