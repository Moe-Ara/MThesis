using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Core.Auditing;
using Core.Policy;
using Core.Planning;

namespace Core.Execution;

public sealed class ExecutionPipeline : IExecutionPipeline
{
    private readonly IExecutorRouter _router;
    private readonly IAuditLogger _auditLogger;

    public ExecutionPipeline(IExecutorRouter router, IAuditLogger? auditLogger = null)
    {
        _router = router ?? throw new ArgumentNullException(nameof(router));
        _auditLogger = auditLogger ?? new NullAuditLogger();
    }

    public Task<ExecutionReport> ExecuteAsync(
        DecisionPlan plan,
        PolicyDecision policy,
        ExecutionContext ctx,
        CancellationToken ct)
        => ExecuteAsync(alert: null!, assessment: null!, plan, policy, ctx, ct);

    public async Task<ExecutionReport> ExecuteAsync(
        EnrichedAlert alert,
        ThreatAssessment assessment,
        DecisionPlan plan,
        PolicyDecision policy,
        ExecutionContext ctx,
        CancellationToken ct)
    {
        if (plan is null) throw new ArgumentNullException(nameof(plan));
        if (policy is null) throw new ArgumentNullException(nameof(policy));
        if (ctx is null) throw new ArgumentNullException(nameof(ctx));

        var correlationId = Guid.NewGuid().ToString("N");
        var approved = new HashSet<string>(policy.Approved.Select(a => a.ActionId), StringComparer.Ordinal);
        var pending = new HashSet<string>(policy.PendingApproval.Select(a => a.ActionId), StringComparer.Ordinal);
        var denied = new HashSet<string>(policy.Denied.Select(a => a.ActionId), StringComparer.Ordinal);

        var results = new List<ActionResult>(plan.Actions.Count);
        var rollbackResults = new List<ActionResult>();
        var notes = new List<string>();

        SafeAuditStart(plan.PlanId, correlationId, ctx);

        foreach (var action in plan.Actions)
        {
            ct.ThrowIfCancellationRequested();

            if (!approved.Contains(action.ActionId))
            {
                var reason = pending.Contains(action.ActionId)
                    ? "Policy pending approval."
                    : denied.Contains(action.ActionId)
                        ? "Denied by policy."
                        : "Not approved by policy.";

                var skipped = BuildResult(action, ActionExecutionStatus.Skipped, "ExecutionPipeline", reason);
                results.Add(skipped);
                continue;
            }

            var startedAtUtc = DateTimeOffset.UtcNow;
            var executor = _router.Resolve(action.Type);
            if (executor is null)
            {
                var result = BuildResult(action, ActionExecutionStatus.Failed, "ExecutionPipeline",
                    "No executor registered.", startedAtUtc);
                results.Add(result);
                SafeAuditAction(plan.PlanId, correlationId, result);
                if (ctx.StopOnFailure) break;
                continue;
            }

            if (ctx.DryRun)
            {
                var check = await RunWithTimeoutAsync(
                    token => executor.CheckAsync(action, ctx, token),
                    ctx.ActionTimeout,
                    ct).ConfigureAwait(false);

                if (!check.CanExecute)
                {
                    var skipped = BuildResult(action, ActionExecutionStatus.Skipped, executor.Name, check.Message, startedAtUtc);
                    results.Add(skipped);
                    SafeAuditAction(plan.PlanId, correlationId, skipped);
                    continue;
                }

                var dryRun = BuildResult(action, ActionExecutionStatus.DryRun, executor.Name, "Dry-run: execution skipped.", startedAtUtc);
                results.Add(dryRun);
                SafeAuditAction(plan.PlanId, correlationId, dryRun);
                continue;
            }

            FeasibilityResult feasibility;
            try
            {
                feasibility = await RunWithTimeoutAsync(
                    token => executor.CheckAsync(action, ctx, token),
                    ctx.ActionTimeout,
                    ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                var timeout = BuildResult(action, ActionExecutionStatus.Failed, executor.Name, "Feasibility check timed out.", startedAtUtc);
                results.Add(timeout);
                SafeAuditAction(plan.PlanId, correlationId, timeout);
                if (ctx.StopOnFailure) break;
                continue;
            }
            catch (Exception ex)
            {
                var failed = BuildResult(action, ActionExecutionStatus.Failed, executor.Name,
                    $"Feasibility check failed: {ex.GetType().Name}: {ex.Message}", startedAtUtc);
                results.Add(failed);
                SafeAuditAction(plan.PlanId, correlationId, failed);
                if (ctx.StopOnFailure) break;
                continue;
            }

            if (!feasibility.CanExecute)
            {
                var skipped = BuildResult(action, ActionExecutionStatus.Skipped, executor.Name, feasibility.Message, startedAtUtc);
                results.Add(skipped);
                SafeAuditAction(plan.PlanId, correlationId, skipped);
                continue;
            }

            ActionResult executionResult;
            try
            {
                var outcome = await RunWithTimeoutAsync(
                    token => executor.ExecuteAsync(action, ctx, token),
                    ctx.ActionTimeout,
                    ct).ConfigureAwait(false);

                executionResult = BuildResult(
                    action,
                    outcome.Succeeded ? ActionExecutionStatus.Succeeded : ActionExecutionStatus.Failed,
                    executor.Name,
                    outcome.Message,
                    startedAtUtc,
                    outcome.ExternalReference);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                executionResult = BuildResult(action, ActionExecutionStatus.Failed, executor.Name, "Execution timed out.", startedAtUtc);
            }
            catch (Exception ex)
            {
                executionResult = BuildResult(action, ActionExecutionStatus.Failed, executor.Name,
                    $"Execution failed: {ex.GetType().Name}: {ex.Message}", startedAtUtc);
            }

            results.Add(executionResult);
            SafeAuditAction(plan.PlanId, correlationId, executionResult);

            if (ctx.StopOnFailure && executionResult.Status == ActionExecutionStatus.Failed)
            {
                notes.Add("Stopped on first failure.");
                if (results.Any(r => r.Status == ActionExecutionStatus.Succeeded))
                {
                    var rollbacks = ExecuteRollbacks(plan, results, correlationId, ctx, ct);
                    rollbackResults.AddRange(rollbacks);
                }
                break;
            }
        }

        SafeAuditEnd(plan.PlanId, correlationId, ctx, results);
        return new ExecutionReport(plan.PlanId, correlationId, results, rollbackResults, notes);
    }

    private static ActionResult BuildResult(
        PlannedAction action,
        ActionExecutionStatus status,
        string executorName,
        string message,
        DateTimeOffset? startedAtUtc = null,
        string? externalReference = null,
        bool isRollback = false,
        string? originalActionId = null)
    {
        var started = startedAtUtc ?? DateTimeOffset.UtcNow;
        var finished = DateTimeOffset.UtcNow;
        return new ActionResult(
            action.ActionId,
            action.Type,
            status,
            executorName,
            started,
            finished,
            message,
            externalReference,
            isRollback,
            originalActionId);
    }

    private void SafeAuditAction(string planId, string correlationId, ActionResult result)
    {
        try
        {
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["planId"] = planId,
                ["actionId"] = result.ActionId,
                ["actionType"] = result.Type.ToString(),
                ["status"] = result.Status.ToString(),
                ["executor"] = result.ExecutorName,
                ["startedAtUtc"] = result.StartedAtUtc.ToString("O"),
                ["finishedAtUtc"] = result.FinishedAtUtc.ToString("O"),
                ["message"] = result.Message
            };

            if (!string.IsNullOrWhiteSpace(result.ExternalReference))
                data["externalReference"] = result.ExternalReference!;
            if (result.IsRollback)
                data["isRollback"] = "true";
            if (!string.IsNullOrWhiteSpace(result.OriginalActionId))
                data["originalActionId"] = result.OriginalActionId!;

            var entry = new AuditEntry(
                EntryId: string.Empty,
                TimestampUtc: DateTimeOffset.UtcNow,
                CorrelationId: correlationId,
                Component: "Execution",
                EventType: "ActionResult",
                Message: result.Message,
                Data: data);

            _auditLogger.Log(entry);
        }
        catch
        {
            // Audit logging must never break execution flow.
        }
    }

    private IReadOnlyList<ActionResult> ExecuteRollbacks(
        DecisionPlan plan,
        IReadOnlyList<ActionResult> results,
        string correlationId,
        ExecutionContext ctx,
        CancellationToken ct)
    {
        var rollbackResults = new List<ActionResult>();
        var rollbackMap = BuildRollbackMap(plan.RollbackActions);

        var succeeded = results
            .Where(r => r.Status == ActionExecutionStatus.Succeeded)
            .Select(r => r.ActionId)
            .ToHashSet(StringComparer.Ordinal);

        foreach (var original in plan.Actions.AsEnumerable().Reverse())
        {
            ct.ThrowIfCancellationRequested();

            if (!succeeded.Contains(original.ActionId))
                continue;

            if (!TryResolveRollbackAction(original, rollbackMap, out var rollback))
            {
                var skipped = BuildResult(original, ActionExecutionStatus.Skipped, "ExecutionPipeline",
                    "No rollback action found.", DateTimeOffset.UtcNow, isRollback: true, originalActionId: original.ActionId);
                rollbackResults.Add(skipped);
                SafeAuditAction(plan.PlanId, correlationId, skipped);
                continue;
            }

            var executor = _router.Resolve(rollback.Type);
            if (executor is null)
            {
                var failed = BuildResult(rollback, ActionExecutionStatus.Failed, "ExecutionPipeline",
                    "No executor registered.", DateTimeOffset.UtcNow, isRollback: true, originalActionId: original.ActionId);
                rollbackResults.Add(failed);
                SafeAuditAction(plan.PlanId, correlationId, failed);
                continue;
            }

            if (ctx.DryRun)
            {
                var dryRun = BuildResult(rollback, ActionExecutionStatus.DryRun, executor.Name,
                    "Dry-run: rollback skipped.", DateTimeOffset.UtcNow, isRollback: true, originalActionId: original.ActionId);
                rollbackResults.Add(dryRun);
                SafeAuditAction(plan.PlanId, correlationId, dryRun);
                continue;
            }

            try
            {
                var feasibility = RunWithTimeoutAsync(
                    token => executor.CheckAsync(rollback, ctx, token),
                    ctx.ActionTimeout,
                    ct).GetAwaiter().GetResult();

                if (!feasibility.CanExecute)
                {
                    var skipped = BuildResult(rollback, ActionExecutionStatus.Skipped, executor.Name,
                        feasibility.Message, DateTimeOffset.UtcNow, isRollback: true, originalActionId: original.ActionId);
                    rollbackResults.Add(skipped);
                    SafeAuditAction(plan.PlanId, correlationId, skipped);
                    continue;
                }

                var outcome = RunWithTimeoutAsync(
                    token => executor.ExecuteAsync(rollback, ctx, token),
                    ctx.ActionTimeout,
                    ct).GetAwaiter().GetResult();

                var status = outcome.Succeeded ? ActionExecutionStatus.Succeeded : ActionExecutionStatus.Failed;
                var result = BuildResult(
                    rollback,
                    status,
                    executor.Name,
                    outcome.Message,
                    DateTimeOffset.UtcNow,
                    outcome.ExternalReference,
                    isRollback: true,
                    originalActionId: original.ActionId);

                rollbackResults.Add(result);
                SafeAuditAction(plan.PlanId, correlationId, result);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                var failed = BuildResult(rollback, ActionExecutionStatus.Failed, executor.Name,
                    "Rollback timed out.", DateTimeOffset.UtcNow, isRollback: true, originalActionId: original.ActionId);
                rollbackResults.Add(failed);
                SafeAuditAction(plan.PlanId, correlationId, failed);
            }
            catch (Exception ex)
            {
                var failed = BuildResult(rollback, ActionExecutionStatus.Failed, executor.Name,
                    $"Rollback failed: {ex.GetType().Name}: {ex.Message}", DateTimeOffset.UtcNow, isRollback: true,
                    originalActionId: original.ActionId);
                rollbackResults.Add(failed);
                SafeAuditAction(plan.PlanId, correlationId, failed);
            }
        }

        return rollbackResults;
    }

    private static Dictionary<string, PlannedAction> BuildRollbackMap(IReadOnlyList<PlannedAction> rollbacks)
    {
        var map = new Dictionary<string, PlannedAction>(StringComparer.Ordinal);
        foreach (var rb in rollbacks)
        {
            map[ActionIdFactory.BuildSignature(rb.Type, rb.Parameters)] = rb;
        }
        return map;
    }

    private static bool TryResolveRollbackAction(
        PlannedAction original,
        IReadOnlyDictionary<string, PlannedAction> rollbackMap,
        out PlannedAction rollback)
    {
        rollback = null!;
        if (!TryGetRollbackType(original.Type, out var rollbackType))
            return false;

        var signature = ActionIdFactory.BuildSignature(rollbackType, original.Parameters);
        return rollbackMap.TryGetValue(signature, out rollback);
    }

    private static bool TryGetRollbackType(ActionType type, out ActionType rollbackType)
    {
        rollbackType = type switch
        {
            ActionType.BlockIp => ActionType.UnblockIp,
            ActionType.IsolateHost => ActionType.UnisolateHost,
            ActionType.DisableUser => ActionType.EnableUser,
            _ => default
        };

        return rollbackType != default;
    }

    private void SafeAuditStart(string planId, string correlationId, ExecutionContext ctx)
    {
        try
        {
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["planId"] = planId,
                ["environment"] = ctx.Environment,
                ["dryRun"] = ctx.DryRun.ToString()
            };

            var entry = new AuditEntry(
                EntryId: string.Empty,
                TimestampUtc: DateTimeOffset.UtcNow,
                CorrelationId: correlationId,
                Component: "Execution",
                EventType: "ExecutionStart",
                Message: "Execution started.",
                Data: data);

            _auditLogger.Log(entry);
        }
        catch
        {
            // Audit logging must never break execution flow.
        }
    }

    private void SafeAuditEnd(
        string planId,
        string correlationId,
        ExecutionContext ctx,
        IReadOnlyList<ActionResult> results)
    {
        try
        {
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["planId"] = planId,
                ["environment"] = ctx.Environment,
                ["dryRun"] = ctx.DryRun.ToString(),
                ["total"] = results.Count.ToString(),
                ["succeeded"] = results.Count(r => r.Status == ActionExecutionStatus.Succeeded).ToString(),
                ["failed"] = results.Count(r => r.Status == ActionExecutionStatus.Failed).ToString(),
                ["skipped"] = results.Count(r => r.Status == ActionExecutionStatus.Skipped).ToString(),
                ["dryRunCount"] = results.Count(r => r.Status == ActionExecutionStatus.DryRun).ToString()
            };

            var entry = new AuditEntry(
                EntryId: string.Empty,
                TimestampUtc: DateTimeOffset.UtcNow,
                CorrelationId: correlationId,
                Component: "Execution",
                EventType: "ExecutionEnd",
                Message: "Execution finished.",
                Data: data);

            _auditLogger.Log(entry);
        }
        catch
        {
            // Audit logging must never break execution flow.
        }
    }

    private static async Task<T> RunWithTimeoutAsync<T>(
        Func<CancellationToken, Task<T>> action,
        TimeSpan timeout,
        CancellationToken ct)
    {
        if (timeout <= TimeSpan.Zero)
            return await action(ct).ConfigureAwait(false);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        return await action(cts.Token).ConfigureAwait(false);
    }
}
