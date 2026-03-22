# Improvement: Sentinel Alert Type Mapping

**Date:** 2026-03-07
**Status:** Deployed and verified

---

## What Was Changed

Added a `MapAlertType()` method to `SentinelAlertMapper` that maps Sentinel incident titles and MITRE tactics to the 5 recognized alert types:

- `BruteForceUser`
- `MalwareHashOnHost`
- `SuspiciousProcessOnHost`
- `PortScanFromIp`
- `PhishingEmailReceived`

The mapping uses:
1. **Title keywords** — e.g., "brute force", "malware", "powershell", "port scan"
2. **MITRE tactics** — from `properties.additionalData.tactics` array

---

## Why This Was Done

Before this change, the `SentinelAlertMapper` passed `raw.AlertType` directly as the normalized alert type, which resolves to the Sentinel incident number (e.g., "201", "202"). This is meaningless to the ML scorer and planner, which were trained on the 5 recognized type names.

After this change:
- Sentinel incident #201 "Suspicious PowerShell Execution" → `SuspiciousProcessOnHost`
- Sentinel incident #202 "Brute Force Attack Against Azure AD" → `BruteForceUser`
- Sentinel incident #203 "Known Malware Hash Detected" → `MalwareHashOnHost`

The classifier scorer and custom NN planner can now correctly classify Sentinel alerts and apply the right strategy, using the same logic they use for Wazuh alerts.

---

## Expected Behavior

### Before
```
Type : 201  |  Severity: 80/100     ← meaningless to the ML models
Score: confidence=50%  "unknown alert type"
Plan : strategy=NotifyOnly          ← wrong strategy
```

### After
```
Type : SuspiciousProcessOnHost  |  Severity: 80/100
Score: confidence=72%  "Suspicious process 'powershell.exe -EncodedCommand...' on ws-finance-03"
Plan : strategy=Contain  priority=81  actions=2
       [APPROVED] OpenTicket
       [PENDING ] IsolateHost  (high-criticality finance asset)
```

---

## Mapping Rules

| Pattern | Mapped Type |
|---------|-------------|
| Title contains "brute force", "credential", "sign-in", "password spray" OR tactic = "CredentialAccess" | `BruteForceUser` |
| Title contains "malware", "ransomware", "trojan", "hash detected" | `MalwareHashOnHost` |
| Title contains "powershell", "encoded command", "suspicious process", "execution", "lateral movement" OR tactics include "Execution", "LateralMovement", "DefenseEvasion" | `SuspiciousProcessOnHost` |
| Title contains "port scan", "reconnaissance" OR tactics include "Reconnaissance", "Discovery" | `PortScanFromIp` |
| Title contains "phishing", "email", "spear" | `PhishingEmailReceived` |
| No match | Falls back to raw alert type from `WebhookAlertListener` |

---

## Files Changed

| File | Change |
|------|--------|
| `NetCore/Core/Connectors/Sentinel/SentinelAlertMapper.cs` | Added `MapAlertType()` method using title keywords and MITRE tactics |
