# Improvement: Rich Console Output for Live Demos

**Date:** 2026-03-07
**Status:** Deployed and verified

---

## What Was Changed

Added a `PrintDemoSummary()` method to `AgentOrchestrator` that is called after each alert is fully processed. It prints a structured, human-readable summary to the console, showing every stage of the pipeline in one glance.

### Output Format

```
────────────────────────────────────────────────────────────────────────
  ALERT  demo-brute-001  [WAZUH]
  Rule : sshd: Multiple failed authentication attempts (possible brute-force).
  Type : BruteForceUser  |  Severity: 67/100
  Asset: 001  criticality=5/5  env=prod
  TI   : reputation=95/100  tags=[tor-exit-node, brute-force, credential-stuffing, scanner]
  Ident: userId=root  privileged=True  dept=System
  Score: confidence=72%  severity=71  "Multiple failed authentication..."
  Plan : strategy=Contain  priority=85  actions=3
         [APPROVED] BlockIp
         [APPROVED] Notify
         [PENDING ] IsolateHost  (requires human approval)
────────────────────────────────────────────────────────────────────────
```

Each block contains:
- **ALERT** line: alert ID and source SIEM
- **Rule**: raw rule name from the SIEM
- **Type**: normalized alert type (after WazuhAlertMapper mapping), plus normalized severity
- **Asset**: asset ID, criticality score, environment (only when enrichment matched)
- **TI**: threat intel reputation score and tags (only when enrichment matched)
- **Ident**: identity context with privilege level (only when enrichment matched)
- **Score**: confidence %, severity, and the model's hypothesis text
- **Plan**: chosen strategy, priority, and total action count
- Per-action lines showing [APPROVED], [PENDING], or [DENIED] status

---

## Why This Was Done

During a live demo in front of a professor or supervisor, the engine was producing no visible output while processing webhook alerts — only the Python replay script printed anything to the terminal.

An interactive demo requires:
1. Immediate visual feedback that the engine received and understood the alert
2. Clear display of enrichment context so the audience can see it affecting decisions
3. Plain-English display of the AI's assessment (hypothesis text)
4. Clear action disposition showing the system's autonomy/approval logic

---

## Expected Behavior

For each alert processed in webhook mode, the console immediately shows the full pipeline summary. The output is designed to be read left-to-right in a live terminal view:

**Verified demo results with 3 production Wazuh alerts:**

```
ALERT  demo-brute-001  [WAZUH]
  → BruteForceUser | Severity 67/100
  → Asset: web-server-prod criticality=5/5 (CRITICAL)
  → TI: 185.220.101.47 reputation=95/100 [tor-exit-node, brute-force]
  → Identity: root (PRIVILEGED)
  → Score: 72% confident — brute-force
  → [APPROVED] BlockIp  [APPROVED] Notify  [PENDING] IsolateHost

ALERT  demo-malware-001  [WAZUH]
  → MalwareHashOnHost | Severity 93/100
  → Asset: finance-laptop-07 criticality=4/5
  → TI: hash 100/100 [trojan, ransomware-dropper, Trojan.GenericKD]
  → Identity: jdoe Finance (non-privileged)
  → Score: 72% confident — malware execution
  → [APPROVED] OpenTicket  [APPROVED] BlockIp  [DENIED] QuarantineFile

ALERT  demo-proc-001  [WAZUH]
  → SuspiciousProcessOnHost | Severity 80/100
  → Asset: hr-workstation-12 criticality=3/5 (below critical threshold)
  → Identity: hsmith HR (non-privileged)
  → Score: 72% confident — suspicious process
  → [APPROVED] IsolateHost  [APPROVED] OpenTicket
```

---

## The Demo Story

The output tells a compelling autonomous response story:

> **BruteForce on critical prod server**: The IP `185.220.101.47` is a known Tor exit node (95/100 reputation). The target is a **critical production web server** (criticality 5/5). The system automatically blocked the IP and sent a notification, but held back from isolating the server — that decision is flagged for human approval because auto-isolating a production server could cause an outage.

> **Malware on finance laptop**: A file hash matching a known trojan (100/100 from VirusTotal) appeared on `finance-laptop-07`. The system opened a ticket and blocked the source IP to prevent lateral movement, but refused to quarantine files on a **high-criticality finance asset** (criticality 4/5) — that action is denied by policy to prevent accidental business disruption.

> **PowerShell from HR workstation**: An encoded PowerShell command was launched from Word on `hr-workstation-12`, a medium-criticality workstation (3/5 — below the critical threshold). Since this isn't a critical asset, the system immediately and autonomously isolated the host and opened a ticket. No human approval needed.

---

## Files Changed

| File | Change |
|------|--------|
| `NetCore/Core/AgentOrchestrator.cs` | Added `PrintDemoSummary()` method called after each alert is processed |
