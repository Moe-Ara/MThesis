# How This System Differs from Traditional SOAR/SIEM

## The Problem with Existing Solutions

Traditional SOAR (Security Orchestration, Automation & Response) and SIEM (Security Information and Event Management) systems like Splunk SOAR, IBM QRadar, and Palo Alto XSOAR rely on:

- **Static, hand-written playbooks**: Fixed if-then decision trees authored manually by security engineers
- **Pre-defined severity thresholds**: Rigid rules like "if failed_logins > 10, severity = high"
- **Human-dependent triage**: Analysts manually review, classify, and decide on every alert
- **No learning or adaptation**: Playbooks don't improve from experience — they remain as brittle as the day they were written
- **Alert fatigue**: Analysts are overwhelmed with false positives because static rules can't distinguish context

## What This System Contributes

### 1. LLM-Driven Threat Assessment (Replacing Static Rules)

Instead of rigid threshold-based scoring, a **fine-tuned cybersecurity LLM** (Foundation-Sec-8B, pre-trained on 5.1B tokens of cybersecurity text) dynamically assesses alerts by understanding context.

**Traditional SOAR:**
```
IF failed_logins > 10 THEN severity = "high"
IF file_hash IN known_malware_list THEN severity = "critical"
```

**This system:**
The LLM reads the full alert context — alert type, raw log data, entity relationships — and produces a nuanced assessment:
```json
{
  "severity": 75,
  "confidence": 0.85,
  "hypothesis": "Credential stuffing attack targeting admin account with high velocity from single source IP",
  "evidence": ["45 failed logins in 5 minutes", "single source IP", "targeting privileged account"]
}
```

The model understands *why* something is dangerous, not just whether a number exceeds a threshold.

**Baseline proof:** Before fine-tuning, the generic baron-security model scores ALL alerts (including obvious malware and brute force) as severity=0, confidence=0. After fine-tuning on 3,270 real security examples derived from MITRE ATT&CK, Mordor, and CIC-IDS2018, the model should accurately discriminate between benign noise and genuine threats.

### 2. Autonomous Response Planning (Replacing Fixed Playbooks)

Instead of executing a pre-written playbook, the LLM **generates contextual response plans** by reasoning about:

- What entities are available in the alert (IP, hostname, user, file hash)
- What actions are appropriate given the confidence level
- Risk vs. impact tradeoffs for each proposed action
- Rollback strategies if an action needs to be reversed

**Traditional SOAR playbook:**
```
ON "BruteForce" DO:
  1. Block source IP
  2. Disable user account
  3. Open ticket
```
This runs identically whether it's 3 failed logins from an internal dev or 500 attempts from an external attacker.

**This system's dynamic plan:**
```json
{
  "strategy": "Contain",
  "priority": 75,
  "actions": [
    {"type": "BlockIp", "parameters": {"src_ip": "172.16.10.5"}, "risk": 40, "reversible": true},
    {"type": "DisableUser", "parameters": {"username": "admin"}, "risk": 60, "reversible": true},
    {"type": "OpenTicket", "risk": 0}
  ],
  "rollbackActions": [
    {"type": "UnblockIp", "parameters": {"src_ip": "172.16.10.5"}},
    {"type": "EnableUser", "parameters": {"username": "admin"}}
  ],
  "rationale": ["High-velocity brute force from single IP warrants containment", "Admin account is high-value target"]
}
```

The plan adapts to the specific alert context. Low-confidence alerts get conservative plans (Notify only). High-confidence attacks get containment with rollback.

### 3. Policy-Gated Autonomy (The Safety Layer)

This is the critical differentiator from both traditional SOAR and from naive "let the AI decide everything" approaches.

A **risk-based policy engine** sits between the LLM's proposed plan and actual execution:

```
LLM proposes action → Policy Engine evaluates → Approve / Deny / Escalate
```

The policy engine enforces rules like:
- **Low-risk actions** (OpenTicket, Notify): Auto-approved, execute immediately
- **Medium-risk actions** (BlockIp): Approved only if scorer confidence ≥ 0.60
- **High-risk actions** (IsolateHost, DisableUser): Require human approval regardless of confidence
- **Destructive actions**: Never auto-executed

This creates **graduated autonomy** — the system handles routine responses automatically while escalating high-impact decisions to humans. Traditional SOAR either runs the whole playbook or doesn't; there's no nuance.

### 4. Domain-Specific Fine-Tuning on Real Threat Data

The intelligence models are not generic chatbots asked to "be a security analyst." They are fine-tuned using QLoRA on:

| Data Source | What It Provides | Count |
|---|---|---|
| **MITRE ATT&CK** | 835 real technique descriptions across 14 tactics (reconnaissance through impact) | ~835 alerts |
| **Mordor/Security-Datasets** | Real Windows event logs from simulated attacks (Sysmon, Security events) | ~700 alerts |
| **CIC-IDS2018** | Labeled network flow data with real attack traffic (DoS, DDoS, Brute Force, SQL Injection, XSS) | ~2,000 alerts |

The training uses an **LLM-assisted generation pipeline**: a capable model (baron-security) generates scorer assessments and response plans for each real alert, creating supervised training pairs. This produces a specialist model that understands the specific alert schema, action catalog, and response patterns used by this system.

### 5. Closed-Loop Architecture

The full pipeline is:

```
Alert Ingestion → Normalization → LLM Scoring → LLM Planning → Policy Gate → Execution → Audit
     (SIEM)         (C# Engine)     (Python)       (Python)      (C# Engine)   (C# Engine)  (JSONL)
```

Every decision is audited — what the LLM scored, what plan it proposed, what the policy engine approved/denied, what was executed. This creates a complete forensic trail and enables post-incident analysis of the AI's decision quality.

## Summary: The Thesis Contribution

> **Can a fine-tuned domain-specific LLM replace static SOAR playbooks with dynamic, context-aware incident response planning while maintaining safety through policy-gated autonomy?**

| Aspect | Traditional SOAR | This System |
|---|---|---|
| Threat assessment | Static rules & thresholds | Fine-tuned LLM contextual analysis |
| Response planning | Fixed playbooks | Dynamic LLM-generated plans |
| Action decisions | All-or-nothing | Graduated autonomy with policy gates |
| Adaptation | Manual playbook updates | Model fine-tuning on new data |
| Context awareness | Pattern matching only | Natural language understanding of alerts |
| Safety guarantees | None (runs what's written) | Risk-based policy engine + human escalation |
| Audit trail | Basic logging | Full decision chain (score → plan → policy → execution) |

The key insight is that **no existing SOAR tool uses LLMs for autonomous decision-making**, and **no existing LLM security tool has a safety-gated execution pipeline**. This system bridges both worlds.
