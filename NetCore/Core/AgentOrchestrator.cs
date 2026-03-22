using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Core.Auditing;
using Core.CaseManagement;
using Core.Demo;
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
    private readonly IDemoTraceWriter? _demoTraceWriter;
    private string? _cursor;
    private DateTimeOffset? _sinceUtc;

    // ── Session statistics (accumulated across all processed alerts) ────────
    private readonly object _statsLock = new();
    private int _statProcessed;
    private int _statTotalApproved;
    private int _statTotalPending;
    private int _statTotalDenied;
    private int _statCriticalAssetAlerts;
    private int _statMaxSeverity;
    private string _statMaxSeverityAlert = string.Empty;
    private readonly Dictionary<string, int> _statBySiem = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _statByStrategy = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _statInvolvedAssets = new(StringComparer.OrdinalIgnoreCase);

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
        ICaseManager? caseManager = null,
        IDemoTraceWriter? demoTraceWriter = null)
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
        _demoTraceWriter = demoTraceWriter;
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

        var demoCorrelationId = Guid.NewGuid().ToString("N");
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
            TryWriteDemoTrace(new DemoTrace(
                CorrelationId: demoCorrelationId,
                TimestampUtc: DateTimeOffset.UtcNow,
                Stage: "NormalizationFailed",
                RawAlert: raw,
                Enriched: null,
                Assessment: null,
                Plan: null,
                Policy: null,
                Execution: null,
                Notes: new Dictionary<string, string>
                {
                    ["error"] = $"{ex.GetType().Name}: {ex.Message}"
                }));
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
            TryWriteDemoTrace(new DemoTrace(
                CorrelationId: demoCorrelationId,
                TimestampUtc: DateTimeOffset.UtcNow,
                Stage: "PlanningFailed",
                RawAlert: raw,
                Enriched: enriched,
                Assessment: assessment,
                Plan: null,
                Policy: null,
                Execution: null,
                Notes: new Dictionary<string, string>
                {
                    ["error"] = $"{ex.GetType().Name}: {ex.Message}"
                }));
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
            TryWriteDemoTrace(new DemoTrace(
                CorrelationId: demoCorrelationId,
                TimestampUtc: DateTimeOffset.UtcNow,
                Stage: "PolicyFailed",
                RawAlert: raw,
                Enriched: enriched,
                Assessment: assessment,
                Plan: plan,
                Policy: null,
                Execution: null,
                Notes: new Dictionary<string, string>
                {
                    ["error"] = $"{ex.GetType().Name}: {ex.Message}"
                }));
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
            TryWriteDemoTrace(new DemoTrace(
                CorrelationId: demoCorrelationId,
                TimestampUtc: DateTimeOffset.UtcNow,
                Stage: "ExecutionFailed",
                RawAlert: raw,
                Enriched: enriched,
                Assessment: assessment,
                Plan: plan,
                Policy: decision,
                Execution: null,
                Notes: new Dictionary<string, string>
                {
                    ["error"] = $"{ex.GetType().Name}: {ex.Message}"
                }));
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

        PrintDemoSummary(raw, enriched, assessment, plan, decision, execReport);
        UpdateSessionStats(raw, enriched, assessment, plan, decision);

        TryWriteDemoTrace(new DemoTrace(
            CorrelationId: demoCorrelationId,
            TimestampUtc: DateTimeOffset.UtcNow,
            Stage: "Completed",
            RawAlert: raw,
            Enriched: enriched,
            Assessment: assessment,
            Plan: plan,
            Policy: decision,
            Execution: execReport));

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

    private void TryWriteDemoTrace(DemoTrace trace)
    {
        if (_demoTraceWriter is null)
            return;
        try
        {
            _demoTraceWriter.Write(trace);
        }
        catch
        {
            // Demo trace must never break orchestration.
        }
    }

    private void UpdateSessionStats(
        RawAlert raw, EnrichedAlert enriched, ThreatAssessment assessment,
        DecisionPlan plan, PolicyDecision decision)
    {
        lock (_statsLock)
        {
            _statProcessed++;
            _statTotalApproved += decision.Approved.Count;
            _statTotalPending  += decision.PendingApproval.Count;
            _statTotalDenied   += decision.Denied.Count;

            _statBySiem.TryGetValue(raw.SiemName, out var siemCount);
            _statBySiem[raw.SiemName] = siemCount + 1;

            var strategyKey = plan.Strategy.ToString();
            _statByStrategy.TryGetValue(strategyKey, out var stratCount);
            _statByStrategy[strategyKey] = stratCount + 1;

            var asset = enriched.Context.Asset;
            if (asset is not null)
            {
                if (asset.Criticality >= 4)
                    _statCriticalAssetAlerts++;
                if (!string.IsNullOrWhiteSpace(asset.AssetId))
                    _statInvolvedAssets.Add(asset.AssetId);
            }

            if (assessment.Severity > _statMaxSeverity)
            {
                _statMaxSeverity = assessment.Severity;
                var display = raw.AlertId.Length > 30
                    ? raw.AlertId[^24..] + ".." : raw.AlertId;
                _statMaxSeverityAlert = $"{display} [{raw.SiemName.ToUpper()}] sev={assessment.Severity}";
            }
        }
    }

    public void PrintExecutiveSummary()
    {
        lock (_statsLock)
        {
            if (_statProcessed == 0)
                return;

            var wide = new string('═', 72);
            var thin = new string('─', 72);
            Console.WriteLine();
            Console.WriteLine(wide);
            Console.WriteLine("  SOAR SESSION SUMMARY");
            Console.WriteLine(thin);
            Console.WriteLine($"  Alerts processed : {_statProcessed}");
            Console.WriteLine($"  Sources          : {string.Join(", ", _statBySiem.Select(kv => $"{kv.Key.ToUpper()}={kv.Value}"))}");
            Console.WriteLine($"  Critical assets  : {_statCriticalAssetAlerts} alert(s) involved criticality ≥ 4 assets");
            Console.WriteLine($"  Assets involved  : {(_statInvolvedAssets.Count > 0 ? string.Join(", ", _statInvolvedAssets) : "(none)")}");
            Console.WriteLine(thin);
            Console.WriteLine("  STRATEGY BREAKDOWN");
            foreach (var kv in _statByStrategy.OrderByDescending(x => x.Value))
                Console.WriteLine($"    {kv.Key,-22} {kv.Value,2} alert(s)");
            Console.WriteLine(thin);
            Console.WriteLine("  ACTIONS SUMMARY");
            Console.WriteLine($"    Auto-executed  (APPROVED) : {_statTotalApproved}");
            Console.WriteLine($"    Awaiting human (PENDING)  : {_statTotalPending}");
            Console.WriteLine($"    Blocked policy (DENIED)   : {_statTotalDenied}");
            Console.WriteLine(thin);
            if (!string.IsNullOrEmpty(_statMaxSeverityAlert))
                Console.WriteLine($"  Highest severity alert     : {_statMaxSeverityAlert}");
            Console.WriteLine(wide);
            Console.WriteLine();
        }
    }

    private static void PrintDemoSummary(
        RawAlert raw,
        EnrichedAlert enriched,
        ThreatAssessment assessment,
        DecisionPlan plan,
        PolicyDecision decision,
        ExecutionReport execReport)
    {
        try
        {
            var sep = Ansi.C(new string('─', 72), Ansi.DimWhite);
            Console.WriteLine();
            Console.WriteLine(sep);

            // Alert header
            var alertDisplay = raw.AlertId.Length > 40
                ? "..." + raw.AlertId[^36..]
                : raw.AlertId;
            Console.WriteLine($"  {Ansi.C("ALERT", Ansi.Bold)}  {Ansi.C(alertDisplay, Ansi.BrightWhite)}  [{Ansi.C(raw.SiemName.ToUpper(), Ansi.Cyan)}]");
            Console.WriteLine($"  Rule : {raw.RuleName ?? "(no rule name)"}");

            var alertType = enriched.Base.AlertType ?? raw.AlertType ?? "(unknown)";
            var sevColor = enriched.Base.Severity >= 70 ? Ansi.BrightRed : enriched.Base.Severity >= 40 ? Ansi.Yellow : Ansi.Reset;
            Console.WriteLine($"  Type : {Ansi.C(alertType, Ansi.Bold)}  |  Severity: {Ansi.C($"{enriched.Base.Severity}/100", sevColor)}");

            // Enrichment context
            var asset = enriched.Context.Asset;
            var identity = enriched.Context.Identity;
            var ti = enriched.Context.ThreatIntel;
            if (asset is not null)
            {
                var critColor = asset.Criticality >= 5 ? Ansi.BrightRed : asset.Criticality >= 4 ? Ansi.Yellow : Ansi.Reset;
                Console.WriteLine($"  Asset: {Ansi.C(asset.AssetId, Ansi.BrightWhite)}  criticality={Ansi.C($"{asset.Criticality}/5", critColor)}  env={asset.Environment ?? "?"}");
            }
            if (ti is not null)
            {
                var tiColor = ti.ReputationScore >= 70 ? Ansi.BrightRed : ti.ReputationScore >= 40 ? Ansi.Yellow : Ansi.Reset;
                Console.WriteLine($"  TI   : reputation={Ansi.C($"{ti.ReputationScore}/100", tiColor)}  tags=[{string.Join(", ", ti.Matches ?? [])}]");
            }
            if (identity is not null)
            {
                var privColor = identity.Privileged ? Ansi.BrightRed : Ansi.Reset;
                Console.WriteLine($"  Ident: userId={identity.UserId ?? "?"}  privileged={Ansi.C(identity.Privileged.ToString(), privColor)}  dept={identity.Department ?? "?"}");
            }

            // Assessment — truncate hypothesis to 100 chars to avoid wrapping
            var confColor = assessment.Confidence >= 0.80 ? Ansi.Green : assessment.Confidence >= 0.60 ? Ansi.Yellow : Ansi.Reset;
            var hyp = assessment.Hypothesis?.Length > 110
                ? assessment.Hypothesis[..107] + "..."
                : assessment.Hypothesis ?? "";
            Console.WriteLine($"  Score: confidence={Ansi.C($"{assessment.Confidence:P0}", confColor)}  severity={Ansi.C($"{assessment.Severity}", sevColor)}");
            Console.WriteLine($"         \"{hyp}\"");

            // Plan
            var stratColor = plan.Strategy.ToString() is "ContainAndCollect" or "Contain" ? Ansi.Green : Ansi.Reset;
            Console.WriteLine($"  Plan : strategy={Ansi.C(plan.Strategy.ToString(), stratColor)}  priority={plan.Priority}  actions={plan.Actions.Count}");

            // Enrichment-driven override notes from planner
            var enrichmentNotes = plan.Rationale
                .Where(r => r.Contains("escalated", StringComparison.OrdinalIgnoreCase)
                         || r.Contains("upgraded", StringComparison.OrdinalIgnoreCase)
                         || r.Contains("added", StringComparison.OrdinalIgnoreCase)
                         || r.Contains("floored", StringComparison.OrdinalIgnoreCase))
                .Take(3)
                .ToList();
            foreach (var note in enrichmentNotes)
                Console.WriteLine($"         {Ansi.C("[NOTE  ]", Ansi.Cyan)} {note}");

            // Build a lookup from action to per-action reasons
            var perActionReasons = decision.PerAction
                .ToDictionary(d => d.Action.ActionId, d => d.Reasons);

            // Policy decisions per action — show first reason for pending/denied, plus key parameter
            foreach (var approved in decision.Approved)
            {
                var param = FormatActionParam(approved);
                Console.WriteLine($"         {Ansi.C("[APPROVED]", Ansi.Green)} {approved.Type}{param}");
            }
            foreach (var pending in decision.PendingApproval)
            {
                var reason = perActionReasons.TryGetValue(pending.ActionId, out var reasons) && reasons.Count > 0
                    ? reasons[0] : "requires human approval";
                var param = FormatActionParam(pending);
                Console.WriteLine($"         {Ansi.C("[PENDING ]", Ansi.Yellow)} {pending.Type}{param}  — {reason}");
            }
            foreach (var denied in decision.Denied)
            {
                var reason = perActionReasons.TryGetValue(denied.ActionId, out var reasons) && reasons.Count > 0
                    ? reasons[0] : "denied by policy";
                var param = FormatActionParam(denied);
                Console.WriteLine($"         {Ansi.C("[DENIED  ]", Ansi.Red)} {denied.Type}{param}  — {reason}");
            }

            Console.WriteLine(sep);
        }
        catch
        {
            // Summary printing must never break orchestration.
        }
    }

    private static string FormatActionParam(PlannedAction action)
    {
        // Show the most informative parameter for each action type inline
        var p = action.Parameters;
        var val = action.Type switch
        {
            ActionType.BlockIp or ActionType.UnblockIp
                => p.TryGetValue("src_ip", out var ip) ? ip : null,
            ActionType.IsolateHost or ActionType.UnisolateHost
                => p.TryGetValue("host_id", out var h) ? h : null,
            ActionType.DisableUser or ActionType.EnableUser
                => p.TryGetValue("username", out var u) ? u : null,
            ActionType.KillProcess
                => p.TryGetValue("process_name", out var proc) ? proc : null,
            ActionType.QuarantineFile
                => p.TryGetValue("file_hash", out var fh) ? fh[..Math.Min(16, fh.Length)] + ".." : null,
            _ => null
        };
        return val is not null ? $"  ({Ansi.C(val, Ansi.DimWhite)})" : string.Empty;
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

/// <summary>
/// ANSI escape code helpers. All colors are no-ops when output is redirected or NO_COLOR is set.
/// </summary>
internal static class Ansi
{
    public static readonly bool Enabled =
        !Console.IsOutputRedirected &&
        string.IsNullOrEmpty(Environment.GetEnvironmentVariable("NO_COLOR"));

    public const string Reset     = "\u001b[0m";
    public const string Bold      = "\u001b[1m";
    public const string DimWhite  = "\u001b[2m";
    public const string Green     = "\u001b[32m";
    public const string Yellow    = "\u001b[33m";
    public const string Red       = "\u001b[31m";
    public const string Cyan      = "\u001b[36m";
    public const string BrightWhite = "\u001b[97m";
    public const string BrightRed   = "\u001b[91m";

    public static string C(string text, string color)
        => Enabled ? color + text + Reset : text;
}
