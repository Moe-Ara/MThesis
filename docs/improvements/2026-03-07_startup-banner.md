# Improvement: Professional Startup Banner

**Date:** 2026-03-07
**Status:** Deployed

---

## What Was Changed

`ProgramHelpers.PrintStartupBanner()` was added and called from `Program.cs` when
the engine starts in webhook mode. It prints a structured system configuration header
before the listener begins accepting alerts.

---

## Why This Was Done

The previous startup sequence printed a few generic lines:
```
Starting intelligence service...
[Enrichment] Loaded 3 provider(s) from 'data/enrichment'.
Webhook listener started on http://localhost:5050/
```

For a live professor demo, the first thing visible on screen should immediately
convey system purpose and configuration, not raw log messages. The banner establishes
context: what the system is, what intelligence model it's using, and that it's
running in safe dry-run mode.

---

## Example Output

```
════════════════════════════════════════════════════════════════════════
║         SOAR ENGINE  —  Autonomous Threat Response System            ║
║                    Thesis Demo  |  2026-03-07                        ║
════════════════════════════════════════════════════════════════════════

  Intelligence    : http://localhost:8000  profile=custom-nn
  Enrichment      : 3 provider(s) loaded  (assets, threat_intel, identities)
  Webhook         : http://localhost:5050/
  Mode            : WEBHOOK  |  DRY-RUN (no real actions)

────────────────────────────────────────────────────────────────────────

  Listening on http://localhost:5050/  (press Ctrl+C to stop and print summary)
```

---

## Color Usage

- Banner border: cyan
- Intelligence URL + webhook: bright white
- Model profile: yellow
- Enrichment count: green (if > 0), yellow (if 0)
- Mode: bold
- DRY-RUN: yellow; LIVE: bright red (to clearly flag when real actions are enabled)

---

## Files Changed

| File | Change |
|------|--------|
| `NetCore/Core/ProgramHelpers.cs` | Added `PrintStartupBanner()` static method |
| `NetCore/Core/Program.cs` | Calls `PrintStartupBanner()` with config values before starting webhook listener |
