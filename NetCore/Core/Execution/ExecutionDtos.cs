using System;
using System.Collections.Generic;

namespace Core.Execution;

public enum ActionExecutionStatus
{
    Skipped,
    DryRun,
    Succeeded,
    Failed
}

public sealed record ActionResult(
    string ActionId,
    ActionType Type,
    ActionExecutionStatus Status,
    string ExecutorName,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset FinishedAtUtc,
    string Message,
    string? ExternalReference = null,
    bool IsRollback = false,
    string? OriginalActionId = null
);

public sealed record ExecutionReport(
    string PlanId,
    string CorrelationId,
    IReadOnlyList<ActionResult> Actions,
    IReadOnlyList<ActionResult> RollbackActions,
    IReadOnlyList<string> Notes
);

public sealed record ExecutionContext(
    string Environment,
    bool DryRun,
    TimeSpan ActionTimeout,
    bool StopOnFailure
);

public sealed record FeasibilityResult(
    bool CanExecute,
    string Message
);

public sealed record ExecutionOutcome(
    bool Succeeded,
    string Message,
    string? ExternalReference = null
);
