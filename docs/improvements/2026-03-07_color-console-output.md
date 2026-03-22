# Improvement: Color Console Output & Action Parameter Display

**Date:** 2026-03-07
**Status:** Deployed

---

## What Was Changed

`PrintDemoSummary` in `AgentOrchestrator` now uses ANSI terminal colors for the
per-alert output, and each action line shows its key parameter (IP address, hostname,
username, process name, or file hash) inline.

A new `Ansi` static helper class provides the color escape codes. Colors are
automatically disabled when output is redirected (`Console.IsOutputRedirected`) or
the `NO_COLOR` environment variable is set (UNIX convention).

---

## Why This Was Done

During a live demo, the console output is the primary visual for the professor.
Monochrome output with uniform text makes it hard to scan quickly. Color allows:

- **Green** `[APPROVED]` to jump out as "the system acted"
- **Yellow** `[PENDING ]` to show "waiting for human approval"
- **Red** `[DENIED  ]` to signal "policy blocked this"
- **Cyan** `[NOTE   ]` for enrichment-driven override explanations
- **Red/yellow** severity and reputation numbers to convey risk level
- **Bright red** criticality=5 asset criticality and privileged identity flag

Adding the key parameter to each action (e.g., `BlockIp  (185.220.101.47)`) answers
the natural question *"block which IP?"* without the professor having to look elsewhere.

---

## Color Scheme

| Element | Color | Condition |
|---------|-------|-----------|
| [APPROVED] | Green | Always |
| [PENDING ] | Yellow | Always |
| [DENIED  ] | Red | Always |
| [NOTE    ] | Cyan | Enrichment override |
| Severity number | Bright red | ≥ 70 |
| Severity number | Yellow | 40–69 |
| TI reputation | Bright red | ≥ 70 |
| Asset criticality | Bright red | = 5 |
| Asset criticality | Yellow | = 4 |
| Confidence % | Green | ≥ 80% |
| Confidence % | Yellow | 60–79% |
| Strategy | Green | Contain / ContainAndCollect |
| privileged flag | Bright red | `true` |
| Alert ID / Asset ID | Bright white | Always |
| SIEM source | Cyan | Always |

---

## Expected Output

```
────────────────────────────────────────────────────────────────────────
  ALERT  demo-brute-001  [WAZUH]
  Rule : sshd: Multiple failed authentication attempts (possible brute-force).
  Type : BruteForceUser  |  Severity: 80/100           ← bright red
  Asset: 001  criticality=5/5  env=prod                ← criticality bright red
  TI   : reputation=95/100  tags=[tor-exit-node, ...]  ← reputation bright red
  Ident: userId=root  privileged=True  dept=System      ← True bright red
  Score: confidence=85%  severity=80  "..."             ← confidence green
  Plan : strategy=ContainAndCollect  priority=85        ← strategy green
         [NOTE  ] Strategy upgraded to ContainAndCollect — critical asset...
         [NOTE  ] CollectForensics added — asset criticality=5/5...
         [APPROVED] BlockIp  (185.220.101.47)           ← green, IP shown
         [APPROVED] CollectForensics
         [PENDING ] IsolateHost  (001)  — Target asset is critical    ← yellow
         [DENIED  ] DisableUser  (root)  — ...           ← red
────────────────────────────────────────────────────────────────────────
```

---

## Files Changed

| File | Change |
|------|--------|
| `NetCore/Core/AgentOrchestrator.cs` | Added `Ansi` helper class, refactored `PrintDemoSummary` with color codes, added `FormatActionParam()` helper |
