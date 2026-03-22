# Improvement: Enrichment Pipeline Activation

**Date:** 2026-03-07
**Status:** Deployed and verified

---

## What Was Changed

Three enrichment providers were wired into the normalization pipeline and their data files were populated with real demo entity data.

### 1. Data Files (`data/enrichment/`)

#### `assets.json` — Asset Inventory
Maps known hostnames and host IDs to criticality ratings and metadata:

| Asset | Host ID | Criticality | Environment | Team |
|-------|---------|-------------|-------------|------|
| web-server-prod | 001 | 5 (Critical) | prod | platform |
| finance-laptop-07 | 003 | 4 (High) | prod | finance |
| hr-workstation-12 | 005 | 3 (Medium) | prod | hr |
| ws-finance-03 | host-203 | 4 (High) | prod | finance |
| laptop-exec-07 | host-507 | 5 (Critical) | prod | executive |

#### `threat_intel.json` — Threat Intelligence
Known malicious IPs and file hashes:

| Indicator | Value | Score | Source | Tags |
|-----------|-------|-------|--------|------|
| IP | 185.220.101.47 | 95/100 | AbuseIPDB | tor-exit-node, brute-force |
| Hash | d41d8cd98f00b204e9800998ecf8427e | 100/100 | VirusTotal | trojan, ransomware-dropper |
| IP | 192.168.10.45 | 0/100 | internal | corporate-network |

#### `identities.json` — Identity Store
Known user accounts with privilege levels:

| Username | Privileged | Department |
|----------|-----------|------------|
| root | Yes | System |
| jdoe | No | Finance |
| hsmith | No | HR |
| hchen | No | Finance |
| admin@contoso.com | Yes | IT |

### 2. Program.cs — Provider Wiring

Replaced:
```csharp
services.AddSingleton<IEnumerable<IEnrichmentProvider>>(_ => Array.Empty<IEnrichmentProvider>());
```

With automatic loading from `data/enrichment/` (or `ENRICHMENT_DATA_PATH` env var):
```csharp
services.AddSingleton<IEnumerable<IEnrichmentProvider>>(_ =>
{
    var enrichmentDir = Environment.GetEnvironmentVariable("ENRICHMENT_DATA_PATH")
                        ?? Path.Combine("data", "enrichment");
    var providers = new List<IEnrichmentProvider>();
    if (File.Exists(assetsPath))   providers.Add(new AssetInventoryEnricher(assetsPath));
    if (File.Exists(tiPath))       providers.Add(new ThreatIntelEnricher(tiPath));
    if (File.Exists(idPath))       providers.Add(new IdentityEnricher(idPath));
    ...
});
```

The providers are optional — missing files are silently skipped. A startup log message confirms how many providers loaded.

---

## Why This Was Done

Real Wazuh alerts often lack rich context. Without enrichment:
- The policy engine cannot distinguish a critical production server from a developer laptop
- The planner cannot know if a username is a privileged service account
- The scorer cannot factor in known-malicious IP reputation

With enrichment:
- Asset criticality (1–5 scale) gates high-impact actions automatically
- Privileged identity flags trigger additional scrutiny for user account actions
- Threat intel matches boost the planner's choice of containment actions

---

## Expected Behavior After This Change

### Demo Alert Results (verified 2026-03-07)

**Alert 1 — SSH Brute-Force (demo-brute-001)**
- Source: `185.220.101.47` → TI score 95 (Tor exit node)
- Target: `web-server-prod` → criticality=5 (Critical)
- Result: `BlockIp` ✅ auto-approved | `Notify` ✅ auto-approved | `IsolateHost` ⏳ pending
- Reason: `IsolateHost` on a criticality-5 prod server requires human approval
  (`requireApprovalOnCriticalAssets` policy gate triggered)

**Alert 2 — Malware Hash (demo-malware-001)**
- Hash: `d41d8cd98f00b204e9800998ecf8427e` → TI score 100 (known trojan)
- Target: `finance-laptop-07` → criticality=4 (High)
- Result: `OpenTicket` ✅ | `BlockIp` ✅ | `QuarantineFile` ❌ denied
- Reason: `QuarantineFile` is in `forbidActionsOnCriticalAssets` — too destructive for a
  high-criticality finance asset without explicit override

**Alert 3 — Suspicious PowerShell (demo-proc-001)**
- Target: `hr-workstation-12` → criticality=3 (Medium) — below the critical threshold
- Result: `IsolateHost` ✅ auto-approved | `OpenTicket` ✅ auto-approved
- Reason: Criticality 3 < threshold 4 → all actions auto-execute immediately

### Demo Narrative

This behavior demonstrates the SOAR agent's risk-proportional autonomy:

> "The system automatically isolated the HR workstation running the suspicious PowerShell process — it's not a critical asset, so the response was immediate. For the production web server under brute-force, the IP was blocked automatically, but isolating a critical prod server requires a human decision. And for the finance laptop where malware was found — we blocked the lateral movement path and opened a ticket, but quarantining files on a finance machine requires explicit approval to avoid business disruption."

---

## How the Enrichment Flows Through the Pipeline

```
RawAlert (Wazuh/Sentinel webhook)
    │
    ▼
NormalizationPipeline.ProcessAsync()
    │
    ├── IAlertMapper.Map()          → NormalizedAlert (type, severity, entities)
    │
    ├── AssetInventoryEnricher      → patch: AssetContext (criticality, environment)
    ├── ThreatIntelEnricher         → patch: ThreatIntelContext (reputationScore, tags)
    ├── IdentityEnricher            → patch: IdentityContext (privileged, department)
    │
    ├── DefaultEnrichmentMerger     → merge all patches into EnrichmentContext
    │
    └── EnrichedAlert (base + context + provenance)
            │
            ├── HttpThreatScorerClient  → sends context.assetCriticality + context.privileged
            │
            ├── HttpPlannerClient       → sends full alert.context
            │
            └── PolicyEngine.Evaluate() → uses enriched.Context.Asset.Criticality
                                          uses enriched.Context.Identity.Privileged
```

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ENRICHMENT_DATA_PATH` | `data/enrichment` | Directory containing enrichment JSON files |

The three JSON files are optional individually. Add new assets/identities/indicators by editing the JSON files — no rebuild required.

To add a new asset:
```json
{
  "hostId": "agent-id-from-wazuh",
  "hostname": "hostname-from-wazuh-agent.name",
  "ip": null,
  "criticality": 3,
  "environment": "prod",
  "owner": "team-name",
  "team": "team-name"
}
```

To add a threat intel indicator:
```json
{
  "srcIp": "1.2.3.4",
  "fileHash": null,
  "reputationScore": 90,
  "source": "AbuseIPDB",
  "tags": ["scanner", "c2"]
}
```

---

## Files Changed

| File | Change |
|------|--------|
| `data/enrichment/assets.json` | Populated with 5 real demo hosts |
| `data/enrichment/threat_intel.json` | Populated with real IPs and hashes |
| `data/enrichment/identities.json` | Populated with real usernames |
| `NetCore/Core/Program.cs` | Wired 3 enrichment providers with file-existence checks |
