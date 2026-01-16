using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Core.Auditing;
using Core.CaseManagement;
using Core.Execution;
using Core.Interfaces;
using Core.NormalizationPipeline;
using Core.Planning;
using Core.Policy;
using Core.Scoring;
using Core.Simulation;
using Xunit;

public sealed class SimulationRunnerTests
{
    [Fact]
    public async Task RunAsync_GeneratesDeterministicReport()
    {
        var mappingRegistry = new SimulationMappingRegistry();
        var normalization = new NormalizationPipeline(
            mappingRegistry,
            new BasicAlertValidator(),
            Array.Empty<IEnrichmentProvider>(),
            new DefaultEnrichmentMerger());

        var stubScorer = new StubThreatScorer();
        var pythonScorer = new PythonThreatScorerAdapter(new PythonThreatScorerClient());

        var planner = new Planner(
            ActionCatalogDefaults.CreateDefault(),
            new BasicStrategySelector(),
            new BasicActionSelector(),
            new BasicRiskEstimator(),
            new BasicRollbackBuilder(),
            new BasicActionNormalizer());

        var approvals = new ApprovalWorkflow();
        var policy = new PolicyEngine(ActionCatalogDefaults.CreateDefault(), approvals);

        var executors = new IActionExecutor[]
        {
            new TicketingExecutor(),
            new NotificationExecutor(),
            new FirewallExecutor(),
            new UserAccessExecutor(),
            new HostIsolationExecutor()
        };
        var router = new ExecutorRouter(executors);

        var tempDir = Path.Combine(Path.GetTempPath(), "core-sim-tests");
        Directory.CreateDirectory(tempDir);
        var auditPath = Path.Combine(tempDir, $"audit-{Guid.NewGuid():N}.jsonl");

        var execution = new ExecutionPipeline(router, new JsonlFileAuditLogger(auditPath));
        var auditPipeline = new JsonlAuditPipeline(auditPath);
        var generator = new ThreatGenerator();
        var runner = new ScenarioRunner(
            normalization,
            stubScorer,
            pythonScorer,
            planner,
            policy,
            approvals,
            execution,
            new JsonlFileAuditLogger(auditPath),
            auditPipeline,
            new NullCaseManager(),
            generator);

        var config = new ThreatGenConfig(
            Seed: 123,
            Count: 5,
            Environment: "dev",
            DryRun: true,
            IncludeEdgeCases: false,
            ScenarioWeights: new Dictionary<string, int>(),
            UsePythonScorer: false,
            ActionTimeout: TimeSpan.FromSeconds(1),
            StopOnFailure: false);

        var report = await runner.RunAsync(config, CancellationToken.None);

        Assert.Equal(5, report.TotalGenerated);
        Assert.Equal(5, report.ScenarioOutcomes.Count);
        Assert.True(report.ExecutionsDryRun > 0);
    }
}
