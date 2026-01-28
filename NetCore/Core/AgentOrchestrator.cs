using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Core.Auditing;
using Core.CaseManagement;
using Core.Execution;
using Core.Interfaces;
using Core.Planning;
using Core.Policy;
using Core.Scoring;

namespace Core;

public sealed class AgentOrchestrator
{
    private readonly ISiemConnector _connector;
    private readonly INormalizationPipeline _normalization;
    private readonly IThreatScorer _scorer;
    private readonly IPlanner _planner;
    private readonly PolicyEngine _policy;
    private readonly ApprovalWorkflow _approvals;
    private readonly IExecutionPipeline _execution;
    private readonly IAuditLogger _auditLogger;
    private readonly IAuditPipeline? _auditPipeline;
    private readonly ICaseManager _caseManager;
    private readonly OrchestratorConfig _config;
    private readonly ActionCatalog _catalog;
    private string? _cursor;
    private DateTimeOffset? _sinceUtc;

    public AgentOrchestrator(
        ISiemConnector connector,
        INormalizationPipeline normalization,
        IThreatScorer scorer,
        IPlanner planner,
        PolicyEngine policy,
        ApprovalWorkflow approvals,
        IExecutionPipeline execution,
        OrchestratorConfig? config = null,
        IAuditLogger? auditLogger = null,
        IAuditPipeline? auditPipeline = null,
        ICaseManager? caseManager = null)
    {
        _connector = connector ?? throw new ArgumentNullException(nameof(connector));
        _normalization = normalization ?? throw new ArgumentNullException(nameof(normalization));
        _scorer = scorer ?? throw new ArgumentNullException(nameof(scorer));
        _planner = planner ?? throw new ArgumentNullException(nameof(planner));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _approvals = approvals ?? throw new ArgumentNullException(nameof(approvals));
        _execution = execution ?? throw new ArgumentNullException(nameof(execution));
        _config = config ?? OrchestratorConfig.Default;
        _auditLogger = auditLogger ?? new NullAuditLogger();
        _auditPipeline = auditPipeline;
        _caseManager = caseManager ?? new NullCaseManager();
        _catalog = _config.Catalog ?? ActionCatalogDefaults.CreateDefault();
        _sinceUtc = _config.SinceUtc;
    }

    public OrchestrationReport RunCycle()
        => RunCycleAsync(CancellationToken.None).GetAwaiter().GetResult();

    public async Task<OrchestrationReport> RunCycleAsync(CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct).ConfigureAwait(false);

        var request = new PullRequest(
            Cursor: _cursor,
            SinceUtc: _cursor is null ? _sinceUtc : null,
            Limit: _config.PullLimit);

        PullResult<RawAlert> result;
        try
        {
            result = await _connector.PullAlertsAsync(request, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            var correlationId = Guid.NewGuid().ToString("N");
            LogEvent(correlationId, "Orchestrator", "PullFailed",
                $"Failed to pull alerts: {ex.GetType().Name}: {ex.Message}",
                new Dictionary<string, string>
                {
                    ["cursor"] = _cursor ?? string.Empty,
                    ["sinceUtc"] = _sinceUtc?.ToString("O") ?? string.Empty
                });

            return new OrchestrationReport(
                Pulled: 0,
                Processed: 0,
                NormalizationFailed: 0,
                PlanningFailed: 0,
                PolicyFailed: 0,
                ExecutionFailed: 0,
                ExecutionSucceeded: 0,
                ExecutionSkipped: 0,
                ExecutionDryRun: 0,
                ApprovalsCreated: 0,
                NextCursor: _cursor);
        }

        var processed = 0;
        var normalizationFailed = 0;
        var planningFailed = 0;
        var policyFailed = 0;
        var executionFailed = 0;
        var executionSucceeded = 0;
        var executionSkipped = 0;
        var executionDryRun = 0;
        var approvalsCreated = 0;

        foreach (var raw in result.Items)
        {
            ct.ThrowIfCancellationRequested();
            var outcome = await HandleAlertInternalAsync(raw, ct).ConfigureAwait(false);
            if (outcome.Processed)
                processed++;
            if (outcome.NormalizationFailed)
                normalizationFailed++;
            if (outcome.PlanningFailed)
                planningFailed++;
            if (outcome.PolicyFailed)
                policyFailed++;
            executionFailed += outcome.ExecutionFailed;
            executionSucceeded += outcome.ExecutionSucceeded;
            executionSkipped += outcome.ExecutionSkipped;
            executionDryRun += outcome.ExecutionDryRun;
            approvalsCreated += outcome.ApprovalsCreated;
        }

        _cursor = result.NextCursor;
        if (result.NextCursor is null)
            _sinceUtc = DateTimeOffset.UtcNow;

        if (_auditPipeline is not null)
        {
            try
            {
                await _auditPipeline.BuildReportAsync(new AuditQuery(FromUtc: DateTimeOffset.UtcNow.AddMinutes(-10)),
                    ct).ConfigureAwait(false);
            }
            catch
            {
                // Audit report generation must not break the run cycle.
            }
        }

        return new OrchestrationReport(
            Pulled: result.Items.Count,
            Processed: processed,
            NormalizationFailed: normalizationFailed,
            PlanningFailed: planningFailed,
            PolicyFailed: policyFailed,
            ExecutionFailed: executionFailed,
            ExecutionSucceeded: executionSucceeded,
            ExecutionSkipped: executionSkipped,
            ExecutionDryRun: executionDryRun,
            ApprovalsCreated: approvalsCreated,
            NextCursor: _cursor);
    }

    public void HandleAlert(RawAlert raw)
        => HandleAlertAsync(raw, CancellationToken.None).GetAwaiter().GetResult();

    public Task HandleAlertAsync(RawAlert raw, CancellationToken ct = default)
        => HandleAlertInternalAsync(raw, ct);

    private async Task<AlertOutcome> HandleAlertInternalAsync(RawAlert raw, CancellationToken ct)
    {
        if (raw is null) throw new ArgumentNullException(nameof(raw));

        var approvalsBefore = _approvals.Requests.Count;
        await TryAckAsync(raw.AlertId, _config.AckOnStartStatus, ct).ConfigureAwait(false);

        EnrichedAlert enriched;
        try
        {
            enriched = await _normalization.ProcessAsync(raw, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            var correlationId = Guid.NewGuid().ToString("N");
            LogEvent(correlationId, "Orchestrator", "NormalizationFailed",
                $"Normalization failed: {ex.GetType().Name}: {ex.Message}",
                BuildAlertData(raw));
            await TryAckAsync(raw.AlertId, AckStatus.InProgress, ct).ConfigureAwait(false);
            return AlertOutcome.NormalizationFailure;
        }

        var assessment = ScoreSafe(enriched);

        DecisionPlan plan;
        PlanningContext planningContext;
        try
        {
            planningContext = new PlanningContext(
                Environment: _config.Environment,
                DryRun: _config.DryRun,
                Catalog: _catalog,
                NowUtc: DateTimeOffset.UtcNow);
            plan = _planner.Plan(enriched, assessment, planningContext);
        }
        catch (Exception ex)
        {
            var correlationId = Guid.NewGuid().ToString("N");
            LogEvent(correlationId, "Orchestrator", "PlanningFailed",
                $"Planning failed: {ex.GetType().Name}: {ex.Message}",
                BuildAlertData(raw));
            await TryAckAsync(raw.AlertId, AckStatus.InProgress, ct).ConfigureAwait(false);
            return AlertOutcome.PlanningFailure;
        }

        PolicyDecision decision;
        try
        {
            decision = _policy.Evaluate(plan, assessment, enriched, planningContext);
        }
        catch (Exception ex)
        {
            var correlationId = Guid.NewGuid().ToString("N");
            LogEvent(correlationId, "Orchestrator", "PolicyFailed",
                $"Policy evaluation failed: {ex.GetType().Name}: {ex.Message}",
                BuildAlertData(raw, plan.PlanId));
            await TryAckAsync(raw.AlertId, AckStatus.InProgress, ct).ConfigureAwait(false);
            return AlertOutcome.PolicyFailure;
        }

        var approvalsAfter = _approvals.Requests.Count;
        var approvalsCreated = Math.Max(0, approvalsAfter - approvalsBefore);

        ExecutionReport execReport;
        try
        {
            var execContext = new Core.Execution.ExecutionContext(
                Environment: _config.Environment,
                DryRun: _config.DryRun,
                ActionTimeout: _config.ActionTimeout,
                StopOnFailure: _config.StopOnFailure);

            execReport = await _execution.ExecuteAsync(enriched, assessment, plan, decision, execContext, ct)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            var correlationId = Guid.NewGuid().ToString("N");
            LogEvent(correlationId, "Orchestrator", "ExecutionFailed",
                $"Execution failed: {ex.GetType().Name}: {ex.Message}",
                BuildAlertData(raw, plan.PlanId));
            await TryAckAsync(raw.AlertId, AckStatus.InProgress, ct).ConfigureAwait(false);
            return new AlertOutcome(
                Processed: true,
                NormalizationFailed: false,
                PlanningFailed: false,
                PolicyFailed: false,
                ExecutionFailed: 1,
                ExecutionSucceeded: 0,
                ExecutionSkipped: 0,
                ExecutionDryRun: 0,
                ApprovalsCreated: approvalsCreated);
        }

        try
        {
            _caseManager.OpenOrUpdate(assessment, plan, decision);
        }
        catch
        {
            // Case management errors should not break alert handling.
        }

        LogEvent(execReport.CorrelationId, "Orchestrator", "AlertProcessed",
            $"Alert {raw.AlertId} processed.",
            BuildAlertData(raw, plan.PlanId, decision));

        var status = ResolveAckStatus(decision, execReport);
        await TryAckAsync(raw.AlertId, status, ct).ConfigureAwait(false);

        return new AlertOutcome(
            Processed: true,
            NormalizationFailed: false,
            PlanningFailed: false,
            PolicyFailed: false,
            ExecutionFailed: execReport.Actions.Count(a => a.Status == ActionExecutionStatus.Failed),
            ExecutionSucceeded: execReport.Actions.Count(a => a.Status == ActionExecutionStatus.Succeeded),
            ExecutionSkipped: execReport.Actions.Count(a => a.Status == ActionExecutionStatus.Skipped),
            ExecutionDryRun: execReport.Actions.Count(a => a.Status == ActionExecutionStatus.DryRun),
            ApprovalsCreated: approvalsCreated);
    }

    private async Task EnsureConnectedAsync(CancellationToken ct)
    {
        if (_connector.IsConnected)
            return;

        await _connector.ConnectAsync(ct).ConfigureAwait(false);
    }

    private async Task TryAckAsync(string alertId, AckStatus status, CancellationToken ct)
    {
        if (!_connector.Capabilities.SupportsAck)
            return;

        if (string.IsNullOrWhiteSpace(alertId))
            return;

        try
        {
            await _connector.AckAsync(alertId, status, ct).ConfigureAwait(false);
        }
        catch
        {
            // Ack failures should not break orchestration.
        }
    }

    private static ThreatAssessment ScoreSafe(IThreatScorer scorer, EnrichedAlert enriched)
    {
        try
        {
            return scorer.Score(enriched);
        }
        catch (Exception ex)
        {
            return new ThreatAssessment(
                Confidence: 0.2,
                Severity: 10,
                Hypothesis: $"Scoring failed: {ex.GetType().Name}",
                Evidence: new List<string> { ex.Message });
        }
    }

    private ThreatAssessment ScoreSafe(EnrichedAlert enriched)
        => ScoreSafe(_scorer, enriched);

    private static AckStatus ResolveAckStatus(PolicyDecision decision, ExecutionReport report)
    {
        if (decision.PendingApproval.Count > 0)
            return AckStatus.InProgress;

        if (report.Actions.Any(a => a.Status == ActionExecutionStatus.Failed))
            return AckStatus.InProgress;

        return AckStatus.Closed;
    }

    private void LogEvent(string correlationId, string component, string eventType, string message,
        Dictionary<string, string> data)
    {
        try
        {
            var entry = new AuditEntry(
                EntryId: string.Empty,
                TimestampUtc: DateTimeOffset.UtcNow,
                CorrelationId: correlationId,
                Component: component,
                EventType: eventType,
                Message: message,
                Data: data);

            _auditLogger.Log(entry);
        }
        catch
        {
            // Audit errors should not break orchestration.
        }
    }

    private static Dictionary<string, string> BuildAlertData(
        RawAlert raw,
        string? planId = null,
        PolicyDecision? decision = null)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["alertId"] = raw.AlertId,
            ["siem"] = raw.SiemName,
            ["timestampUtc"] = raw.TimestampUtc.ToString("O")
        };

        if (!string.IsNullOrWhiteSpace(raw.AlertType))
            data["alertType"] = raw.AlertType!;
        if (!string.IsNullOrWhiteSpace(raw.RuleName))
            data["ruleName"] = raw.RuleName!;
        if (raw.OriginalSeverity.HasValue)
            data["originalSeverity"] = raw.OriginalSeverity.Value.ToString();
        if (!string.IsNullOrWhiteSpace(planId))
            data["planId"] = planId!;
        if (decision is not null)
        {
            data["approved"] = decision.Approved.Count.ToString();
            data["pending"] = decision.PendingApproval.Count.ToString();
            data["denied"] = decision.Denied.Count.ToString();
        }

        return data;
    }

    private sealed record AlertOutcome(
        bool Processed,
        bool NormalizationFailed,
        bool PlanningFailed,
        bool PolicyFailed,
        int ExecutionFailed,
        int ExecutionSucceeded,
        int ExecutionSkipped,
        int ExecutionDryRun,
        int ApprovalsCreated)
    {
        public static AlertOutcome NormalizationFailure => new(
            Processed: false,
            NormalizationFailed: true,
            PlanningFailed: false,
            PolicyFailed: false,
            ExecutionFailed: 0,
            ExecutionSucceeded: 0,
            ExecutionSkipped: 0,
            ExecutionDryRun: 0,
            ApprovalsCreated: 0);

        public static AlertOutcome PlanningFailure => new(
            Processed: false,
            NormalizationFailed: false,
            PlanningFailed: true,
            PolicyFailed: false,
            ExecutionFailed: 0,
            ExecutionSucceeded: 0,
            ExecutionSkipped: 0,
            ExecutionDryRun: 0,
            ApprovalsCreated: 0);

        public static AlertOutcome PolicyFailure => new(
            Processed: false,
            NormalizationFailed: false,
            PlanningFailed: false,
            PolicyFailed: true,
            ExecutionFailed: 0,
            ExecutionSucceeded: 0,
            ExecutionSkipped: 0,
            ExecutionDryRun: 0,
            ApprovalsCreated: 0);
    }
}

public sealed record OrchestratorConfig(
    string Environment,
    bool DryRun,
    TimeSpan ActionTimeout,
    bool StopOnFailure,
    int PullLimit = 200,
    DateTimeOffset? SinceUtc = null,
    ActionCatalog? Catalog = null,
    AckStatus AckOnStartStatus = AckStatus.Seen)
{
    public static OrchestratorConfig Default => new(
        Environment: "dev",
        DryRun: true,
        ActionTimeout: TimeSpan.FromSeconds(30),
        StopOnFailure: false);
}

public sealed record OrchestrationReport(
    int Pulled,
    int Processed,
    int NormalizationFailed,
    int PlanningFailed,
    int PolicyFailed,
    int ExecutionFailed,
    int ExecutionSucceeded,
    int ExecutionSkipped,
    int ExecutionDryRun,
    int ApprovalsCreated,
    string? NextCursor);
