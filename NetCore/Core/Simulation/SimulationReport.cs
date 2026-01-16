using System;
using System.Collections.Generic;

namespace Core.Simulation;

public sealed record ScenarioOutcome(
    string ScenarioId,
    string ScenarioType,
    string CorrelationId,
    int Approved,
    int Pending,
    int Denied,
    int ExecSucceeded,
    int ExecFailed,
    int ExecSkipped,
    int ExecDryRun,
    string Summary
);

public sealed record SimulationReport(
    int TotalGenerated,
    int PlansCreated,
    int PolicyApproved,
    int PolicyPending,
    int PolicyDenied,
    int ApprovalsCreated,
    int ExecutionsSucceeded,
    int ExecutionsFailed,
    int ExecutionsSkipped,
    int ExecutionsDryRun,
    int UnknownActionsEncountered,
    TimeSpan AvgNormalizeEnrichTime,
    TimeSpan AvgPlanningTime,
    TimeSpan AvgPolicyTime,
    TimeSpan AvgExecutionTime,
    IReadOnlyList<ScenarioOutcome> ScenarioOutcomes,
    IReadOnlyList<string> CorrelationIds
);
