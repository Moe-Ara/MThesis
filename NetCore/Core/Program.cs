using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Core;
using Core.Auditing;
using Core.CaseManagement;
using Core.Connectors.Wazuh;
using Core.Execution;
using Core.Interfaces;
using Core.NormalizationPipeline;
using Core.Notification;
using Core.Planning;
using Core.Policy;
using Core.Scoring;
using Core.Simulation;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
var wazuhBaseUrl = Environment.GetEnvironmentVariable("WAZUH_API_BASEURL");
var scorerBaseUrl = Environment.GetEnvironmentVariable("THREAT_SCORER_BASEURL");
var plannerBaseUrl = Environment.GetEnvironmentVariable("PLANNER_API_BASEURL");
var policyConfigPath = Environment.GetEnvironmentVariable("POLICY_CONFIG_PATH");
var ticketingBaseUrl = Environment.GetEnvironmentVariable("TICKETING_API_BASEURL");
var notificationBaseUrl = Environment.GetEnvironmentVariable("NOTIFICATION_API_BASEURL");
var firewallBaseUrl = Environment.GetEnvironmentVariable("FIREWALL_API_BASEURL");
var pollSeconds = ProgramHelpers.GetIntEnv("ORCHESTRATOR_POLL_SECONDS", 30);
var maxCycles = ProgramHelpers.GetIntEnv("ORCHESTRATOR_MAX_CYCLES", 0);
var webhookUrl = Environment.GetEnvironmentVariable("ORCHESTRATOR_WEBHOOK_URL");

// --- Auditing ---
var auditPath = Path.Combine("data", "audit.jsonl");
services.AddSingleton<IAuditLogger>(_ => new JsonlFileAuditLogger(auditPath));
services.AddSingleton<IAuditPipeline>(_ => new JsonlAuditPipeline(auditPath));

// --- Execution ---
if (!string.IsNullOrWhiteSpace(ticketingBaseUrl))
    services.AddSingleton<IActionExecutor>(_ => new HttpTicketingExecutor(new TicketingApiOptions(ticketingBaseUrl, Environment.GetEnvironmentVariable("TICKETING_API_KEY"))));
else
    services.AddSingleton<IActionExecutor, TicketingExecutor>();

if (!string.IsNullOrWhiteSpace(notificationBaseUrl))
    services.AddSingleton<IActionExecutor>(_ => new HttpNotificationExecutor(new NotificationApiOptions(notificationBaseUrl, Environment.GetEnvironmentVariable("NOTIFICATION_API_KEY"))));
else
    services.AddSingleton<IActionExecutor, NotificationExecutor>();

if (!string.IsNullOrWhiteSpace(firewallBaseUrl))
    services.AddSingleton<IActionExecutor>(_ => new HttpFirewallExecutor(new FirewallApiOptions(firewallBaseUrl, Environment.GetEnvironmentVariable("FIREWALL_API_KEY"), 30)));
else
    services.AddSingleton<IActionExecutor, FirewallExecutor>();
services.AddSingleton<IActionExecutor, UserAccessExecutor>();
services.AddSingleton<IActionExecutor, HostIsolationExecutor>();
services.AddSingleton<IExecutorRouter, ExecutorRouter>();
services.AddSingleton<IExecutionPipeline, ExecutionPipeline>();

// --- Normalization ---
if (!string.IsNullOrWhiteSpace(wazuhBaseUrl))
{
    services.AddSingleton<IMappingRegistry, WazuhMappingRegistry>();
}
else
{
    services.AddSingleton<IMappingRegistry, SimulationMappingRegistry>();
}
services.AddSingleton<IAlertValidator, BasicAlertValidator>();
services.AddSingleton<IEnrichmentMerger, DefaultEnrichmentMerger>();
services.AddSingleton<IEnumerable<IEnrichmentProvider>>(_ => Array.Empty<IEnrichmentProvider>());
services.AddSingleton<INormalizationPipeline>(sp => new NormalizationPipeline(
    sp.GetRequiredService<IMappingRegistry>(),
    sp.GetRequiredService<IAlertValidator>(),
    sp.GetRequiredService<IEnumerable<IEnrichmentProvider>>(),
    sp.GetRequiredService<IEnrichmentMerger>()));

// --- Scoring ---
if (!string.IsNullOrWhiteSpace(scorerBaseUrl))
{
    services.AddSingleton<IThreatScorer>(_ =>
        new HttpThreatScorerClient(new ThreatScorerApiOptions(scorerBaseUrl, Environment.GetEnvironmentVariable("THREAT_SCORER_API_KEY"), 30)));
}
else
{
    services.AddSingleton<IThreatScorer, StubThreatScorer>();
}

// --- Planning + policy ---
services.AddSingleton<ActionCatalog>(_ => ActionCatalogDefaults.CreateDefault());
if (!string.IsNullOrWhiteSpace(plannerBaseUrl))
{
    services.AddSingleton<IPlanner>(sp =>
    {
        var fallback = new Planner(
            sp.GetRequiredService<ActionCatalog>(),
            new BasicStrategySelector(),
            new BasicActionSelector(),
            new BasicRiskEstimator(),
            new BasicRollbackBuilder(),
            new BasicActionNormalizer(),
            new BasicActionSanitizer());

        var options = HttpPlannerOptions.FromEnvironment();
        var client = new HttpPlannerClient(options);
        return new HttpPlannerAdapter(client, fallback);
    });
}
else
{
    services.AddSingleton<IPlanner>(sp => new Planner(
        sp.GetRequiredService<ActionCatalog>(),
        new BasicStrategySelector(),
        new BasicActionSelector(),
        new BasicRiskEstimator(),
        new BasicRollbackBuilder(),
        new BasicActionNormalizer(),
        new BasicActionSanitizer()));
}
services.AddSingleton<ApprovalWorkflow>();
services.AddSingleton<PolicyEngine>(sp =>
{
    var config = !string.IsNullOrWhiteSpace(policyConfigPath)
        ? PolicyConfig.LoadFromJson(policyConfigPath, PolicyConfig.Default)
        : PolicyConfig.Default;
    return new PolicyEngine(
        sp.GetRequiredService<ActionCatalog>(),
        sp.GetRequiredService<ApprovalWorkflow>(),
        config);
});

// --- Case management ---
services.AddSingleton<ICaseManager, NullCaseManager>();

// --- SIEM connector ---
if (!string.IsNullOrWhiteSpace(wazuhBaseUrl))
{
    services.AddSingleton<ISiemConnector>(_ =>
        new WazuhSiemConnector(WazuhApiOptions.FromEnvironment()));
}
else
{
    services.AddSingleton<ISiemConnector>(_ =>
    {
        var generator = new ThreatGenerator();
        var config = new ThreatGenConfig(
            Seed: 123,
            Count: 6,
            Environment: "dev",
            DryRun: true,
            IncludeEdgeCases: true,
            ScenarioWeights: new Dictionary<string, int>(),
            UsePythonScorer: false,
            ActionTimeout: TimeSpan.FromSeconds(2),
            StopOnFailure: false);

        var alerts = generator.Generate(config).Select(t => t.Raw).ToList();
        return new InMemorySiemConnector("simulator", alerts);
    });
}

services.AddSingleton(_ => new OrchestratorConfig(
    Environment: "dev",
    DryRun: true,
    ActionTimeout: TimeSpan.FromSeconds(2),
    StopOnFailure: false));
services.AddSingleton<AgentOrchestrator>();

var provider = services.BuildServiceProvider();
var orchestrator = provider.GetRequiredService<AgentOrchestrator>();

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

if (!string.IsNullOrWhiteSpace(webhookUrl))
{
    var listener = new WebhookAlertListener(webhookUrl);
    Console.WriteLine($"Webhook listener started on {webhookUrl}");
    await listener.RunAsync(alert => orchestrator.HandleAlertAsync(alert, cts.Token), cts.Token);
}
else
{
    var cycle = 0;
    while (!cts.IsCancellationRequested)
    {
        cycle++;
        var report = await orchestrator.RunCycleAsync(cts.Token);
        Console.WriteLine(
            $"Orchestrator cycle {cycle} complete. Pulled={report.Pulled} Processed={report.Processed} " +
            $"Succeeded={report.ExecutionSucceeded} Failed={report.ExecutionFailed} " +
            $"NormalizationFailed={report.NormalizationFailed} PolicyFailed={report.PolicyFailed}.");

        if (maxCycles > 0 && cycle >= maxCycles)
            break;

        if (pollSeconds <= 0)
            break;

        try
        {
            await Task.Delay(TimeSpan.FromSeconds(pollSeconds), cts.Token);
        }
        catch (OperationCanceledException)
        {
            break;
        }
    }
}

internal sealed class InMemorySiemConnector : ISiemConnector
{
    private readonly string _name;
    private readonly List<RawAlert> _alerts;
    private bool _connected;

    public InMemorySiemConnector(string name, IEnumerable<RawAlert> alerts)
    {
        _name = name;
        _alerts = alerts?.ToList() ?? new List<RawAlert>();
        Capabilities = new SiemConnectorCapabilities(
            SupportsAck: true,
            SupportsSubscribe: false,
            SupportsPull: true);
    }

    public string Name => _name;
    public bool IsConnected => _connected;
    public SiemConnectorCapabilities Capabilities { get; }

    public Task ConnectAsync(CancellationToken ct)
    {
        _connected = true;
        return Task.CompletedTask;
    }

    public Task DisconnectAsync(CancellationToken ct)
    {
        _connected = false;
        return Task.CompletedTask;
    }

    public Task<PullResult<RawAlert>> PullAlertsAsync(PullRequest request, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var filtered = _alerts;
        if (request.SinceUtc.HasValue)
        {
            filtered = filtered
                .Where(a => a.TimestampUtc >= request.SinceUtc.Value)
                .ToList();
        }

        var start = 0;
        if (!string.IsNullOrWhiteSpace(request.Cursor) &&
            int.TryParse(request.Cursor, out var idx) &&
            idx >= 0)
        {
            start = idx;
        }

        var limit = request.Limit <= 0 ? filtered.Count : request.Limit;
        var items = filtered.Skip(start).Take(limit).ToList();
        var nextIndex = start + items.Count;
        var hasMore = nextIndex < filtered.Count;
        var nextCursor = hasMore ? nextIndex.ToString() : null;

        return Task.FromResult(new PullResult<RawAlert>(items, nextCursor, hasMore));
    }

    public Task AckAsync(string alertId, AckStatus status, CancellationToken ct)
        => Task.CompletedTask;

    public Task SubscribeAsync(SubscriptionRequest request, CancellationToken ct)
        => Task.CompletedTask;

    public Task UnsubscribeAsync(string subscriptionId, CancellationToken ct)
        => Task.CompletedTask;

    public Task<ConnectorHealth> GetHealthAsync(CancellationToken ct)
        => Task.FromResult(new ConnectorHealth(true, "ok", DateTimeOffset.UtcNow));
}
