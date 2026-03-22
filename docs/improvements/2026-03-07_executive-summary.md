# Improvement: Executive Summary After Demo Run

**Date:** 2026-03-07
**Status:** Deployed

---

## What Was Changed

`AgentOrchestrator` now accumulates per-alert statistics into a thread-safe session
counter and exposes `PrintExecutiveSummary()`. When running in webhook mode, `Program.cs`
calls this method immediately after the listener exits (Ctrl+C), so the demo ends with
a clean summary table.

---

## Why This Was Done

During a live professor demo, pressing Ctrl+C after replaying all 14 alerts previously
produced no closing output — the terminal just returned to the prompt. A session summary
makes it immediately obvious what the engine decided across the full alert set, without
the professor having to scroll up and mentally tally results.

---

## Example Output

```
════════════════════════════════════════════════════════════════════════
  SOAR SESSION SUMMARY
────────────────────────────────────────────────────────────────────────
  Alerts processed : 14
  Sources          : WAZUH=11, SENTINEL=3
  Critical assets  : 5 alert(s) involved criticality ≥ 4 assets
  Assets involved  : 001, 003, host-203, host-507
────────────────────────────────────────────────────────────────────────
  STRATEGY BREAKDOWN
    ContainAndCollect      6 alert(s)
    Contain                5 alert(s)
    NotifyOnly             2 alert(s)
    ObserveMore            1 alert(s)
────────────────────────────────────────────────────────────────────────
  ACTIONS SUMMARY
    Auto-executed  (APPROVED) : 28
    Awaiting human (PENDING)  :  8
    Blocked policy (DENIED)   :  3
────────────────────────────────────────────────────────────────────────
  Highest severity alert     : demo-brute-001 [WAZUH] sev=80
════════════════════════════════════════════════════════════════════════
```

---

## Implementation

Stats are accumulated in `AgentOrchestrator.UpdateSessionStats()` — a private method
called from `HandleAlertInternalAsync()` after each alert's `PrintDemoSummary()`. A
`lock` object protects the counters since webhook requests are handled on background threads.

Tracked per session:
- Total alerts processed
- Counts by SIEM source (Wazuh, Sentinel)
- Counts by strategy (Contain, ContainAndCollect, etc.)
- Number of alerts involving criticality ≥ 4 assets
- Asset IDs involved across the session
- Total approved / pending / denied action counts
- The highest-severity alert seen

`PrintExecutiveSummary()` is public and called in `Program.cs` after the webhook listener
exits cleanly (Ctrl+C triggers `CancellationToken`, `RunAsync` returns, then summary prints).

---

## Files Changed

| File | Change |
|------|--------|
| `NetCore/Core/AgentOrchestrator.cs` | Added `_stats*` fields, `UpdateSessionStats()`, `PrintExecutiveSummary()` |
| `NetCore/Core/Program.cs` | Call `orchestrator.PrintExecutiveSummary()` after webhook listener exits |
