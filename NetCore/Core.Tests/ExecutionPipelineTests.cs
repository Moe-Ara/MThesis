using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Core.Execution;
using Core.Auditing;
using Core.Planning;
using Core.Policy;
using Xunit;
using ExecutionContext = Core.Execution.ExecutionContext;
using System.IO;
using System.Text.Json;

public sealed class ExecutionPipelineTests
{
    [Fact]
    public async Task DryRun_ApprovedActions_ReturnsDryRunResults()
    {
        var executors = new IActionExecutor[]
        {
            new TicketingExecutor(),
            new NotificationExecutor(),
            new FirewallExecutor()
        };
        var router = new ExecutorRouter(executors);
        var pipeline = new ExecutionPipeline(router, new NullAuditLogger());

        var actions = new List<PlannedAction>
        {
            BuildAction(ActionType.OpenTicket, new Dictionary<string, string>()),
            BuildAction(ActionType.Notify, new Dictionary<string, string>()),
            BuildAction(ActionType.BlockIp, new Dictionary<string, string> { ["src_ip"] = "1.2.3.4" })
        };

        var plan = new DecisionPlan(
            PlanId: "plan-1",
            Strategy: PlanStrategy.NotifyOnly,
            Priority: 50,
            Summary: "test",
            Actions: actions,
            RollbackActions: new List<PlannedAction>(),
            Rationale: new List<string>());

        var decisions = actions
            .Select(a => new PolicyActionDecision(a, PolicyActionStatus.Approved, new[] { "ok" }))
            .ToList();
        var policy = PolicyDecision.FromActionDecisions(decisions, new[] { "approved" });

        var ctx = new ExecutionContext(
            Environment: "dev",
            DryRun: true,
            ActionTimeout: TimeSpan.FromSeconds(1),
            StopOnFailure: false);

        var report = await pipeline.ExecuteAsync(plan, policy, ctx, CancellationToken.None);

        Assert.Equal(3, report.Actions.Count);
        Assert.All(report.Actions, result => Assert.Equal(ActionExecutionStatus.DryRun, result.Status));
        Assert.DoesNotContain(report.Actions, result => result.Status == ActionExecutionStatus.Failed);
        Assert.Empty(report.RollbackActions);
    }

    [Fact]
    public async Task FileAuditLogger_WritesJsonLinesWithCorrelationId()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "core-audit-tests");
        Directory.CreateDirectory(tempDir);
        var path = Path.Combine(tempDir, $"audit-{Guid.NewGuid():N}.jsonl");

        var executors = new IActionExecutor[] { new TicketingExecutor() };
        var router = new ExecutorRouter(executors);
        var pipeline = new ExecutionPipeline(router, new JsonlFileAuditLogger(path));

        var action = BuildAction(ActionType.OpenTicket, new Dictionary<string, string>());
        var plan = new DecisionPlan(
            PlanId: "plan-audit",
            Strategy: PlanStrategy.NotifyOnly,
            Priority: 50,
            Summary: "test",
            Actions: new List<PlannedAction> { action },
            RollbackActions: new List<PlannedAction>(),
            Rationale: new List<string>());

        var policy = PolicyDecision.FromActionDecisions(
            new[] { new PolicyActionDecision(action, PolicyActionStatus.Approved, new[] { "ok" }) },
            new[] { "approved" });

        var ctx = new ExecutionContext("dev", true, TimeSpan.FromSeconds(1), false);
        var report = await pipeline.ExecuteAsync(plan, policy, ctx, CancellationToken.None);

        var lines = File.ReadAllLines(path);
        Assert.True(lines.Length >= 3);

        foreach (var line in lines)
        {
            var entry = JsonSerializer.Deserialize<AuditEntry>(line, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            Assert.NotNull(entry);
            Assert.Equal(report.CorrelationId, entry!.CorrelationId);
            Assert.False(string.IsNullOrWhiteSpace(entry.EventType));
        }
    }

    [Fact]
    public async Task PendingAndDenied_AreSkipped()
    {
        var executors = new IActionExecutor[] { new TicketingExecutor() };
        var router = new ExecutorRouter(executors);
        var pipeline = new ExecutionPipeline(router, new NullAuditLogger());

        var approved = BuildAction(ActionType.OpenTicket, new Dictionary<string, string>());
        var pending = BuildAction(ActionType.Notify, new Dictionary<string, string>());
        var denied = BuildAction(ActionType.BlockIp, new Dictionary<string, string> { ["src_ip"] = "1.2.3.4" });

        var plan = new DecisionPlan(
            PlanId: "plan-2",
            Strategy: PlanStrategy.NotifyOnly,
            Priority: 50,
            Summary: "test",
            Actions: new List<PlannedAction> { approved, pending, denied },
            RollbackActions: new List<PlannedAction>(),
            Rationale: new List<string>());

        var decisions = new List<PolicyActionDecision>
        {
            new(approved, PolicyActionStatus.Approved, new[] { "ok" }),
            new(pending, PolicyActionStatus.PendingApproval, new[] { "pending" }),
            new(denied, PolicyActionStatus.Denied, new[] { "no" })
        };
        var policy = PolicyDecision.FromActionDecisions(decisions, new[] { "mixed" });

        var ctx = new ExecutionContext("dev", false, TimeSpan.FromSeconds(1), false);
        var report = await pipeline.ExecuteAsync(plan, policy, ctx, CancellationToken.None);

        Assert.Equal(3, report.Actions.Count);
        Assert.Contains(report.Actions, r => r.ActionId == pending.ActionId && r.Status == ActionExecutionStatus.Skipped);
        Assert.Contains(report.Actions, r => r.ActionId == denied.ActionId && r.Status == ActionExecutionStatus.Skipped);
        Assert.Empty(report.RollbackActions);
    }

    [Fact]
    public async Task MissingExecutor_FailsButDoesNotThrow()
    {
        var executors = new IActionExecutor[] { new TicketingExecutor() };
        var router = new ExecutorRouter(executors);
        var pipeline = new ExecutionPipeline(router, new NullAuditLogger());

        var action = BuildAction(ActionType.BlockIp, new Dictionary<string, string> { ["src_ip"] = "1.2.3.4" });
        var plan = new DecisionPlan(
            PlanId: "plan-3",
            Strategy: PlanStrategy.NotifyOnly,
            Priority: 50,
            Summary: "test",
            Actions: new List<PlannedAction> { action },
            RollbackActions: new List<PlannedAction>(),
            Rationale: new List<string>());

        var policy = PolicyDecision.FromActionDecisions(
            new[] { new PolicyActionDecision(action, PolicyActionStatus.Approved, new[] { "ok" }) },
            new[] { "approved" });

        var ctx = new ExecutionContext("dev", false, TimeSpan.FromSeconds(1), false);
        var report = await pipeline.ExecuteAsync(plan, policy, ctx, CancellationToken.None);

        Assert.Single(report.Actions);
        Assert.Equal(ActionExecutionStatus.Failed, report.Actions[0].Status);
        Assert.Contains("No executor", report.Actions[0].Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(report.RollbackActions);
    }

    [Fact]
    public async Task StopOnFailure_StopsAfterFirstFailure()
    {
        var executors = new IActionExecutor[] { new FailingExecutor() };
        var router = new ExecutorRouter(executors);
        var pipeline = new ExecutionPipeline(router, new NullAuditLogger());

        var a1 = BuildAction(ActionType.Notify, new Dictionary<string, string>());
        var a2 = BuildAction(ActionType.OpenTicket, new Dictionary<string, string>());

        var plan = new DecisionPlan(
            PlanId: "plan-4",
            Strategy: PlanStrategy.NotifyOnly,
            Priority: 50,
            Summary: "test",
            Actions: new List<PlannedAction> { a1, a2 },
            RollbackActions: new List<PlannedAction>(),
            Rationale: new List<string>());

        var decisions = new List<PolicyActionDecision>
        {
            new(a1, PolicyActionStatus.Approved, new[] { "ok" }),
            new(a2, PolicyActionStatus.Approved, new[] { "ok" })
        };
        var policy = PolicyDecision.FromActionDecisions(decisions, new[] { "approved" });

        var ctx = new ExecutionContext("dev", false, TimeSpan.FromSeconds(1), true);
        var report = await pipeline.ExecuteAsync(plan, policy, ctx, CancellationToken.None);

        Assert.Single(report.Actions);
        Assert.Equal(ActionExecutionStatus.Failed, report.Actions[0].Status);
        Assert.Empty(report.RollbackActions);
    }

    [Fact]
    public async Task StopOnFailure_RollsBackSucceededActionsInReverse()
    {
        var executors = new IActionExecutor[] { new SelectiveExecutor() };
        var router = new ExecutorRouter(executors);
        var pipeline = new ExecutionPipeline(router, new NullAuditLogger());

        var block = BuildAction(ActionType.BlockIp, new Dictionary<string, string> { ["src_ip"] = "1.2.3.4" });
        var notify = BuildAction(ActionType.Notify, new Dictionary<string, string>());
        var rollback = BuildAction(ActionType.UnblockIp, new Dictionary<string, string> { ["src_ip"] = "1.2.3.4" });

        var plan = new DecisionPlan(
            PlanId: "plan-rollback",
            Strategy: PlanStrategy.NotifyOnly,
            Priority: 50,
            Summary: "test",
            Actions: new List<PlannedAction> { block, notify },
            RollbackActions: new List<PlannedAction> { rollback },
            Rationale: new List<string>());

        var decisions = new List<PolicyActionDecision>
        {
            new(block, PolicyActionStatus.Approved, new[] { "ok" }),
            new(notify, PolicyActionStatus.Approved, new[] { "ok" })
        };
        var policy = PolicyDecision.FromActionDecisions(decisions, new[] { "approved" });

        var ctx = new ExecutionContext("dev", false, TimeSpan.FromSeconds(1), true);
        var report = await pipeline.ExecuteAsync(plan, policy, ctx, CancellationToken.None);

        Assert.Equal(2, report.Actions.Count);
        Assert.Single(report.RollbackActions);
        var rb = report.RollbackActions[0];
        Assert.True(rb.IsRollback);
        Assert.Equal(block.ActionId, rb.OriginalActionId);
        Assert.Equal(ActionType.UnblockIp, rb.Type);
    }

    private static PlannedAction BuildAction(ActionType type, IReadOnlyDictionary<string, string> parameters)
        => new(
            ActionId: ActionIdFactory.Create(type, parameters),
            Type: type,
            Risk: 10,
            ExpectedImpact: 10,
            Reversible: false,
            Duration: null,
            Parameters: new Dictionary<string, string>(parameters),
            Rationale: "test");

    private sealed class FailingExecutor : IActionExecutor
    {
        public string Name => "FailingExecutor";
        public bool CanExecute(ActionType type) => true;
        public Task<FeasibilityResult> CheckAsync(PlannedAction action, ExecutionContext ctx, CancellationToken ct)
            => Task.FromResult(new FeasibilityResult(true, "ok"));
        public Task<ExecutionOutcome> ExecuteAsync(PlannedAction action, ExecutionContext ctx, CancellationToken ct)
            => Task.FromResult(new ExecutionOutcome(false, "failed"));
    }

    private sealed class SelectiveExecutor : IActionExecutor
    {
        public string Name => "SelectiveExecutor";
        public bool CanExecute(ActionType type) => true;
        public Task<FeasibilityResult> CheckAsync(PlannedAction action, ExecutionContext ctx, CancellationToken ct)
            => Task.FromResult(new FeasibilityResult(true, "ok"));
        public Task<ExecutionOutcome> ExecuteAsync(PlannedAction action, ExecutionContext ctx, CancellationToken ct)
        {
            if (action.Type == ActionType.Notify)
                return Task.FromResult(new ExecutionOutcome(false, "failed"));
            return Task.FromResult(new ExecutionOutcome(true, "ok"));
        }
    }
}
