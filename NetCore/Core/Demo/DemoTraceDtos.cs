using System;
using System.Collections.Generic;

namespace Core.Demo;

public sealed record DemoTrace(
    string CorrelationId,
    DateTimeOffset TimestampUtc,
    string Stage,
    RawAlert RawAlert,
    EnrichedAlert? Enriched,
    ThreatAssessment? Assessment,
    DecisionPlan? Plan,
    Policy.PolicyDecision? Policy,
    Execution.ExecutionReport? Execution,
    IReadOnlyDictionary<string, string>? Notes = null,
    IReadOnlyList<Auditing.AuditEntry>? AuditEntries = null
);
