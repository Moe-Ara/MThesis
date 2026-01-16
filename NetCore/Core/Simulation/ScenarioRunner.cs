using System;
using System.Collections.Generic;
using System.Diagnostics;
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
using ExecutionContext = Core.Execution.ExecutionContext;

namespace Core.Simulation;

public sealed class ScenarioRunner : IScenarioRunner
{
    private readonly INormalizationPipeline _normalization;
    private readonly IThreatScorer _stubScorer;
    private readonly IThreatScorer _pythonScorer;
    private readonly IPlanner _planner;
    private readonly PolicyEngine _policy;
    private readonly ApprovalWorkflow _approvals;
    private readonly IExecutionPipeline _execution;
    private readonly IAuditLogger _auditLogger;
    private readonly IAuditPipeline _auditPipeline;
    private readonly ICaseManager _caseManager;
    private readonly IThreatGenerator _generator;

    public ScenarioRunner(
        INormalizationPipeline normalization,
        IThreatScorer stubScorer,
        IThreatScorer pythonScorer,
        IPlanner planner,
        PolicyEngine policy,
        ApprovalWorkflow approvals,
        IExecutionPipeline execution,
        IAuditLogger auditLogger,
        IAuditPipeline auditPipeline,
        ICaseManager? caseManager,
        IThreatGenerator generator)
    {
        _normalization = normalization ?? throw new ArgumentNullException(nameof(normalization));
        _stubScorer = stubScorer ?? throw new ArgumentNullException(nameof(stubScorer));
        _pythonScorer = pythonScorer ?? throw new ArgumentNullException(nameof(pythonScorer));
        _planner = planner ?? throw new ArgumentNullException(nameof(planner));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _approvals = approvals ?? throw new ArgumentNullException(nameof(approvals));
        _execution = execution ?? throw new ArgumentNullException(nameof(execution));
        _auditLogger = auditLogger ?? new NullAuditLogger();
        _auditPipeline = auditPipeline ?? throw new ArgumentNullException(nameof(auditPipeline));
        _caseManager = caseManager ?? new NullCaseManager();
        _generator = generator ?? throw new ArgumentNullException(nameof(generator));
    }

    public async Task<SimulationReport> RunAsync(ThreatGenConfig config, CancellationToken ct = default)
    {
        if (config is null) throw new ArgumentNullException(nameof(config));

        var generated = _generator.Generate(config);
        var outcomes = new List<ScenarioOutcome>(generated.Count);
        var correlationIds = new List<string>(generated.Count);

        var totalPlans = 0;
        var approved = 0;
        var pending = 0;
        var denied = 0;
        var approvalsCreated = 0;
        var execSucceeded = 0;
        var execFailed = 0;
        var execSkipped = 0;
        var execDryRun = 0;
        var unknownActions = 0;

        var normalizeSum = TimeSpan.Zero;
        var planningSum = TimeSpan.Zero;
        var policySum = TimeSpan.Zero;
        var executionSum = TimeSpan.Zero;
        var normalizeCount = 0;
        var planningCount = 0;
        var policyCount = 0;
        var executionCount = 0;

        foreach (var threat in generated)
        {
            ct.ThrowIfCancellationRequested();

            var correlationId = string.Empty;
            var startedAtUtc = DateTimeOffset.UtcNow;

            EnrichedAlert enriched;
            var sw = Stopwatch.StartNew();
            try
            {
                enriched = await _normalization.ProcessAsync(threat.Raw, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                sw.Stop();
                normalizeSum += sw.Elapsed;
                normalizeCount++;

                correlationId = Guid.NewGuid().ToString("N");
                correlationIds.Add(correlationId);

                LogEvent(correlationId, "Simulation", "ThreatStart",
                    $"Scenario {threat.ScenarioType} started.",
                    new Dictionary<string, string>
                    {
                        ["scenarioId"] = threat.ScenarioId,
                        ["scenarioType"] = threat.ScenarioType,
                        ["startedAtUtc"] = startedAtUtc.ToString("O")
                    });

                LogEvent(correlationId, "Simulation", "NormalizationFailed",
                    $"Normalization failed: {ex.GetType().Name}: {ex.Message}",
                    new Dictionary<string, string>
                    {
                        ["scenarioId"] = threat.ScenarioId,
                        ["scenarioType"] = threat.ScenarioType
                    });

                outcomes.Add(new ScenarioOutcome(
                    threat.ScenarioId,
                    threat.ScenarioType,
                    correlationId,
                    Approved: 0,
                    Pending: 0,
                    Denied: 0,
                    ExecSucceeded: 0,
                    ExecFailed: 0,
                    ExecSkipped: 0,
                    ExecDryRun: 0,
                    Summary: "Normalization failed."));
                continue;
            }
            sw.Stop();
            normalizeSum += sw.Elapsed;
            normalizeCount++;

            enriched = AttachScenarioTags(enriched, threat);

            var scorer = config.UsePythonScorer ? _pythonScorer : _stubScorer;
            var assessment = scorer.Score(enriched);

            sw.Restart();
            var planningContext = new PlanningContext(
                Environment: config.Environment,
                DryRun: config.DryRun,
                Catalog: ActionCatalogDefaults.CreateDefault(),
                NowUtc: DateTimeOffset.UtcNow);

            var plan = _planner.Plan(enriched, assessment, planningContext);
            sw.Stop();
            planningSum += sw.Elapsed;
            planningCount++;
            totalPlans++;

            var approvalsBefore = _approvals.Requests.Count;
            sw.Restart();
            var decision = _policy.Evaluate(plan, assessment, enriched, planningContext);
            sw.Stop();
            policySum += sw.Elapsed;
            policyCount++;

            var approvalsAfter = _approvals.Requests.Count;
            approvalsCreated += Math.Max(0, approvalsAfter - approvalsBefore);

            approved += decision.Approved.Count;
            pending += decision.PendingApproval.Count;
            denied += decision.Denied.Count;
            unknownActions += decision.PerAction.Count(d =>
                d.Status == PolicyActionStatus.Denied &&
                d.Reasons.Any(r => r.Contains("Unknown or unsupported action type.", StringComparison.OrdinalIgnoreCase)));

            var execContext = new ExecutionContext(
                Environment: config.Environment,
                DryRun: config.DryRun,
                ActionTimeout: config.ActionTimeout,
                StopOnFailure: config.StopOnFailure);

            sw.Restart();
            var execReport = await _execution.ExecuteAsync(enriched, assessment, plan, decision, execContext, ct)
                .ConfigureAwait(false);
            sw.Stop();
            executionSum += sw.Elapsed;
            executionCount++;

            execSucceeded += execReport.Actions.Count(a => a.Status == ActionExecutionStatus.Succeeded);
            execFailed += execReport.Actions.Count(a => a.Status == ActionExecutionStatus.Failed);
            execSkipped += execReport.Actions.Count(a => a.Status == ActionExecutionStatus.Skipped);
            execDryRun += execReport.Actions.Count(a => a.Status == ActionExecutionStatus.DryRun);

            _caseManager.OpenOrUpdate(assessment, plan, decision);

            correlationId = execReport.CorrelationId;
            correlationIds.Add(correlationId);

            LogEvent(correlationId, "Simulation", "ThreatStart",
                $"Scenario {threat.ScenarioType} started.",
                new Dictionary<string, string>
                {
                    ["scenarioId"] = threat.ScenarioId,
                    ["scenarioType"] = threat.ScenarioType,
                    ["startedAtUtc"] = startedAtUtc.ToString("O")
                });

            LogEvent(correlationId, "Simulation", "ThreatEnd",
                $"Scenario {threat.ScenarioType} completed.",
                new Dictionary<string, string>
                {
                    ["planId"] = plan.PlanId,
                    ["approved"] = decision.Approved.Count.ToString(),
                    ["pending"] = decision.PendingApproval.Count.ToString(),
                    ["denied"] = decision.Denied.Count.ToString()
                });

            outcomes.Add(new ScenarioOutcome(
                threat.ScenarioId,
                threat.ScenarioType,
                correlationId,
                Approved: decision.Approved.Count,
                Pending: decision.PendingApproval.Count,
                Denied: decision.Denied.Count,
                ExecSucceeded: execReport.Actions.Count(a => a.Status == ActionExecutionStatus.Succeeded),
                ExecFailed: execReport.Actions.Count(a => a.Status == ActionExecutionStatus.Failed),
                ExecSkipped: execReport.Actions.Count(a => a.Status == ActionExecutionStatus.Skipped),
                ExecDryRun: execReport.Actions.Count(a => a.Status == ActionExecutionStatus.DryRun),
                Summary: plan.Summary));
        }

        try
        {
            await _auditPipeline.BuildReportAsync(new AuditQuery(), ct).ConfigureAwait(false);
        }
        catch
        {
            // Audit pipeline errors must not break simulation.
        }

        return new SimulationReport(
            TotalGenerated: generated.Count,
            PlansCreated: totalPlans,
            PolicyApproved: approved,
            PolicyPending: pending,
            PolicyDenied: denied,
            ApprovalsCreated: approvalsCreated,
            ExecutionsSucceeded: execSucceeded,
            ExecutionsFailed: execFailed,
            ExecutionsSkipped: execSkipped,
            ExecutionsDryRun: execDryRun,
            UnknownActionsEncountered: unknownActions,
            AvgNormalizeEnrichTime: Average(normalizeSum, normalizeCount),
            AvgPlanningTime: Average(planningSum, planningCount),
            AvgPolicyTime: Average(policySum, policyCount),
            AvgExecutionTime: Average(executionSum, executionCount),
            ScenarioOutcomes: outcomes,
            CorrelationIds: correlationIds);
    }

    private static TimeSpan Average(TimeSpan total, int count)
        => count == 0 ? TimeSpan.Zero : TimeSpan.FromMilliseconds(total.TotalMilliseconds / count);

    private void LogEvent(string correlationId, string component, string eventType, string message, Dictionary<string, string> data)
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
            // Swallow audit errors.
        }
    }

    private static EnrichedAlert AttachScenarioTags(EnrichedAlert alert, GeneratedThreat threat)
    {
        var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (alert.Context.Tags is not null)
        {
            foreach (var kv in alert.Context.Tags)
                tags[kv.Key] = kv.Value;
        }

        foreach (var kv in threat.ExpectedTags)
            tags[kv.Key] = kv.Value;

        tags["scenario_id"] = threat.ScenarioId;
        tags["ground_truth"] = threat.GroundTruth;

        var updatedContext = alert.Context with { Tags = tags };
        return new EnrichedAlert(alert.Base, updatedContext, alert.Provenance);
    }
}
