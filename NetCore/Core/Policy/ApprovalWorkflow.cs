using System;
using System.Collections.Generic;
using System.Linq;

namespace Core.Policy;

/// <summary>
/// Tracks approval requests for actions and provides approve/deny operations.
/// Idempotent by ActionId: you won't create multiple requests for the same action.
/// </summary>
public sealed class ApprovalWorkflow
{
    // Keyed by ActionId for idempotency and easy lookup from PolicyEngine/Executor.
    private readonly Dictionary<string, ApprovalRequest> _requests = new(StringComparer.Ordinal);

    public IReadOnlyCollection<ApprovalRequest> Requests => _requests.Values.ToList();

    /// <summary>
    /// Creates approval requests for actions that need approval.
    /// If a request already exists for an action, it is not recreated.
    /// </summary>
    public IReadOnlyList<ApprovalRequest> CreateRequests(IEnumerable<PlannedAction> actions, string reason)
    {
        if (actions is null) throw new ArgumentNullException(nameof(actions));
        reason ??= "Approval required.";

        var created = new List<ApprovalRequest>();

        foreach (var action in actions)
        {
            if (action is null) continue;

            // Idempotency: one request per action id.
            if (_requests.ContainsKey(action.ActionId))
                continue;

            var request = new ApprovalRequest(
                RequestId: Guid.NewGuid().ToString("N"),
                ActionSnapshot: action,
                Reason: reason,
                RequestedAtUtc: DateTimeOffset.UtcNow,
                Status: ApprovalStatus.Pending
            );

            _requests[action.ActionId] = request;
            created.Add(request);
        }

        return created;
    }

    /// <summary>
    /// Approve an action request by ActionId.
    /// </summary>
    public bool Approve(string actionId) => UpdateStatus(actionId, ApprovalStatus.Approved);

    /// <summary>
    /// Deny an action request by ActionId.
    /// </summary>
    public bool Deny(string actionId) => UpdateStatus(actionId, ApprovalStatus.Denied);

    public ApprovalStatus? GetStatus(string actionId)
        => _requests.TryGetValue(actionId, out var req) ? req.Status : null;

    public ApprovalRequest? GetRequest(string actionId)
        => _requests.TryGetValue(actionId, out var req) ? req : null;

    /// <summary>
    /// Returns only actions that have been explicitly approved (by ActionId).
    /// Useful for turning PendingApproval -> Approved over time.
    /// </summary>
    public IReadOnlyList<PlannedAction> GetApprovedActions(IEnumerable<PlannedAction> pendingActions)
    {
        if (pendingActions is null) throw new ArgumentNullException(nameof(pendingActions));

        return pendingActions
            .Where(a => a is not null)
            .Where(a => GetStatus(a.ActionId) == ApprovalStatus.Approved)
            .ToList();
    }

    private bool UpdateStatus(string actionId, ApprovalStatus status)
    {
        if (string.IsNullOrWhiteSpace(actionId))
            return false;

        if (!_requests.TryGetValue(actionId, out var req))
            return false;

        // Prevent changing a final decision (optional guardrail)
        if (req.Status is ApprovalStatus.Approved or ApprovalStatus.Denied)
            return false;

        _requests[actionId] = req with { Status = status };
        return true;
    }
}
