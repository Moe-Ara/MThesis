using System;
using System.Collections.Generic;
using System.Linq;

namespace Core.Policy;

/// <summary>
/// Result of policy evaluation for a single planned action.
/// </summary>
public enum PolicyActionStatus
{
    Approved,
    PendingApproval,
    Denied
}

/// <summary>
/// Per-action policy outcome + reasons (best for auditing and thesis discussion).
/// </summary>
public sealed record PolicyActionDecision(
    PlannedAction Action,
    PolicyActionStatus Status,
    IReadOnlyList<string> Reasons
);

/// <summary>
/// Outcome of evaluating a decision plan against policy gates (summary + per-action details).
/// </summary>
public sealed record PolicyDecision(
    IReadOnlyList<PlannedAction> Approved,
    IReadOnlyList<PlannedAction> PendingApproval,
    IReadOnlyList<PlannedAction> Denied,
    IReadOnlyList<string> Notes,
    IReadOnlyList<PolicyActionDecision> PerAction
)
{
    public static PolicyDecision FromActionDecisions(
        IReadOnlyList<PolicyActionDecision> decisions,
        IReadOnlyList<string> notes)
    {
        var approved = decisions.Where(d => d.Status == PolicyActionStatus.Approved).Select(d => d.Action).ToList();
        var pending  = decisions.Where(d => d.Status == PolicyActionStatus.PendingApproval).Select(d => d.Action).ToList();
        var denied   = decisions.Where(d => d.Status == PolicyActionStatus.Denied).Select(d => d.Action).ToList();

        return new PolicyDecision(approved, pending, denied, notes, decisions);
    }
}


/// <summary>
/// Represents an approval request for a planned action.
/// Store enough info so a human can understand what they are approving.
/// </summary>
public sealed record ApprovalRequest(
    string RequestId,
    PlannedAction ActionSnapshot,
    string Reason,
    DateTimeOffset RequestedAtUtc,
    ApprovalStatus Status = ApprovalStatus.Pending
);

public enum ApprovalStatus
{
    Pending,
    Approved,
    Denied
}