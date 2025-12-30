public sealed record PullRequest(
    string? Cursor,
    DateTimeOffset? SinceUtc,
    int Limit = 200);

public sealed record PullResult<T>(
    IReadOnlyList<T> Items,
    string? NextCursor,
    bool HasMore);

public enum AckStatus { Seen, InProgress, Closed, FalsePositive }

public sealed record SubscriptionRequest(
    Uri CallbackUrl,
    string? FilterQuery,
    string? Secret);

public sealed record SiemConnectorCapabilities(
    bool SupportsAck,
    bool SupportsSubscribe,
    bool SupportsPull);

public sealed record ConnectorHealth(
    bool Ok,
    string? Message,
    DateTimeOffset CheckedAtUtc);
public sealed record PlanningContext(
    string Environment,                 // "prod", "dev"
    bool DryRun,                        // planner can tag actions as dry-run friendly
    ActionCatalog Catalog,              // what actions exist
    DateTimeOffset NowUtc
);
public enum PlanStrategy
{
    ObserveMore,
    NotifyOnly,
    Contain,
    ContainAndCollect,
    EscalateToHuman
}

public sealed record DecisionPlan(
    string PlanId,
    PlanStrategy Strategy,
    int Priority,                         // 0..100
    string Summary,                       // one-liner
    IReadOnlyList<PlannedAction> Actions,
    IReadOnlyList<PlannedAction> RollbackActions,
    IReadOnlyList<string> Rationale,      // bullet points
    IReadOnlyDictionary<string, string>? Tags = null
);
public enum ActionType
{
    BlockIp,
    UnblockIp,
    IsolateHost,
    UnisolateHost,
    DisableUser,
    EnableUser,
    KillProcess,
    QuarantineFile,
    OpenTicket,
    Notify,
    CollectForensics
}

public sealed record PlannedAction(
    string ActionId,
    ActionType Type,
    int Risk,                              // 0..100 (planner estimate)
    int ExpectedImpact,                    // 0..100 (ops impact)
    bool Reversible,
    TimeSpan? Duration,                    // for temporary actions like IP block
    IReadOnlyDictionary<string, string> Parameters,
    string Rationale
);

public sealed record ActionDefinition(
    ActionType Type,
    bool SupportsRollback,
    bool RequiresApprovalByDefault,
    int DefaultRisk,
    int DefaultImpact,
    IReadOnlyList<string>? RequiredParameters = null
);


public sealed record ActionCatalog(IReadOnlyDictionary<ActionType, ActionDefinition> Items)
{
    public ActionDefinition Get(ActionType t) => Items[t];
}
