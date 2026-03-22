using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Core;
using Core.Auditing;
using Core.CaseManagement;
using Core.Connectors;
using Core.Connectors.Wazuh;
using Core.Demo;
using Core.Execution;
using Core.Intelligence;
using Core.Interfaces;
using Core.NormalizationPipeline;
using Core.Notification;
using Core.Planning;
using Core.Policy;
using Core.Scoring;
using Core.Simulation;
using Microsoft.Extensions.DependencyInjection;

// Load .env file so all Environment.GetEnvironmentVariable calls work
EnvFileLoader.Load();

// Start the Python intelligence service (scorer + planner via Ollama)
using var intelligence = new IntelligenceProcessManager();
await intelligence.StartAsync();

var services = new ServiceCollection();
var wazuhBaseUrl = Environment.GetEnvironmentVariable("WAZUH_API_BASEURL");
var scorerBaseUrl = Environment.GetEnvironmentVariable("THREAT_SCORER_BASEURL");
var plannerBaseUrl = Environment.GetEnvironmentVariable("PLANNER_API_BASEURL");
var policyConfigPath = Environment.GetEnvironmentVariable("POLICY_CONFIG_PATH");
var caseDbPath = Environment.GetEnvironmentVariable("CASE_DB_PATH");
var ticketingBaseUrl = Environment.GetEnvironmentVariable("TICKETING_API_BASEURL");
var notificationBaseUrl = Environment.GetEnvironmentVariable("NOTIFICATION_API_BASEURL");
var firewallBaseUrl = Environment.GetEnvironmentVariable("FIREWALL_API_BASEURL");
var pollSeconds = ProgramHelpers.GetIntEnv("ORCHESTRATOR_POLL_SECONDS", 30);
var maxCycles = ProgramHelpers.GetIntEnv("ORCHESTRATOR_MAX_CYCLES", 0);
var webhookUrl = Environment.GetEnvironmentVariable("ORCHESTRATOR_WEBHOOK_URL");
var simulatorCount = ProgramHelpers.GetIntEnv("SIMULATOR_ALERT_COUNT", 6);
var simulatorIncludeEdgeCases = ProgramHelpers.GetBoolEnv("SIMULATOR_INCLUDE_EDGE_CASES", true);
var simulatorForceScenario = Environment.GetEnvironmentVariable("SIMULATOR_FORCE_SCENARIO");
var orchestratorDryRun = ProgramHelpers.GetBoolEnv("ORCHESTRATOR_DRY_RUN", true);
var orchestratorStopOnFailure = ProgramHelpers.GetBoolEnv("ORCHESTRATOR_STOP_ON_FAILURE", false);
var orchestratorActionTimeoutSeconds = ProgramHelpers.GetIntEnv("ORCHESTRATOR_ACTION_TIMEOUT_SECONDS", 2);
var caseDbEnabled = ProgramHelpers.GetBoolEnv("CASE_DB_ENABLE", false);

static string? NormalizeOptionalBaseUrl(string? url)
{
    if (string.IsNullOrWhiteSpace(url))
        return null;
    var trimmed = url.Trim();
    return trimmed.Contains("example", StringComparison.OrdinalIgnoreCase) ? null : trimmed;
}

ticketingBaseUrl = NormalizeOptionalBaseUrl(ticketingBaseUrl);
notificationBaseUrl = NormalizeOptionalBaseUrl(notificationBaseUrl);
firewallBaseUrl = NormalizeOptionalBaseUrl(firewallBaseUrl);

if (string.IsNullOrWhiteSpace(caseDbPath) && caseDbEnabled)
    caseDbPath = Path.Combine("data", "cases.db");
if (!string.IsNullOrWhiteSpace(caseDbPath))
{
    var caseDbDir = Path.GetDirectoryName(caseDbPath);
    if (!string.IsNullOrWhiteSpace(caseDbDir))
        Directory.CreateDirectory(caseDbDir);
}

// Default to the local intelligence service if explicit URLs are not provided.
if (string.IsNullOrWhiteSpace(scorerBaseUrl))
    scorerBaseUrl = intelligence.BaseUrl;
if (string.IsNullOrWhiteSpace(plannerBaseUrl))
    plannerBaseUrl = intelligence.BaseUrl;

// --- Auditing ---
var auditPath = Path.Combine("data", "audit.jsonl");
services.AddSingleton<IAuditLogger>(_ => new JsonlFileAuditLogger(auditPath));
services.AddSingleton<IAuditPipeline>(_ => new JsonlAuditPipeline(auditPath));

// --- Demo trace (optional) ---
var demoTracePath = Environment.GetEnvironmentVariable("DEMO_TRACE_PATH");
var demoTraceJsonl = Environment.GetEnvironmentVariable("DEMO_TRACE_JSONL_PATH");
var demoTraceOnlySuccess = Environment.GetEnvironmentVariable("DEMO_TRACE_ONLY_SUCCESS");
if (!string.IsNullOrWhiteSpace(demoTracePath))
{
    var onlyOnCompleted = string.Equals(demoTraceOnlySuccess, "true", StringComparison.OrdinalIgnoreCase);
    var auditMax = ProgramHelpers.GetIntEnv("DEMO_TRACE_MAX_AUDIT", 50);
    services.AddSingleton<IDemoTraceWriter>(_ => new JsonDemoTraceWriter(
        demoTracePath,
        demoTraceJsonl,
        onlyOnCompleted,
        auditPath: auditPath,
        maxAuditEntries: auditMax));
}

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
else if (!string.IsNullOrWhiteSpace(webhookUrl))
{
    // Webhook mode: support Wazuh, Sentinel, and other SIEMs via X-Siem-Name header
    services.AddSingleton<IMappingRegistry, MultiSiemMappingRegistry>();
}
else
{
    services.AddSingleton<IMappingRegistry, SimulationMappingRegistry>();
}
services.AddSingleton<IAlertValidator, BasicAlertValidator>();
services.AddSingleton<IEnrichmentMerger, DefaultEnrichmentMerger>();
services.AddSingleton<IEnumerable<IEnrichmentProvider>>(_ =>
{
    var enrichmentDir = Environment.GetEnvironmentVariable("ENRICHMENT_DATA_PATH")
                        ?? Path.Combine("data", "enrichment");
    var providers = new List<IEnrichmentProvider>();
    var assetsPath = Path.Combine(enrichmentDir, "assets.json");
    var tiPath     = Path.Combine(enrichmentDir, "threat_intel.json");
    var idPath     = Path.Combine(enrichmentDir, "identities.json");
    if (File.Exists(assetsPath)) providers.Add(new AssetInventoryEnricher(assetsPath));
    if (File.Exists(tiPath))     providers.Add(new ThreatIntelEnricher(tiPath));
    if (File.Exists(idPath))     providers.Add(new IdentityEnricher(idPath));
    if (providers.Count > 0)
        Console.WriteLine($"[Enrichment] Loaded {providers.Count} provider(s) from '{enrichmentDir}'.");
    return providers;
});
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

        var options = HttpPlannerOptions.FromEnvironment(plannerBaseUrl);
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
if (!string.IsNullOrWhiteSpace(caseDbPath))
    services.AddSingleton<ICaseManager>(_ => new SqliteCaseManager(caseDbPath));
else
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
            Count: simulatorCount,
            Environment: "dev",
            DryRun: orchestratorDryRun,
            IncludeEdgeCases: simulatorIncludeEdgeCases,
            ScenarioWeights: new Dictionary<string, int>(),
            ForceScenario: string.IsNullOrWhiteSpace(simulatorForceScenario) ? null : simulatorForceScenario,
            UsePythonScorer: false,
            ActionTimeout: TimeSpan.FromSeconds(orchestratorActionTimeoutSeconds),
            StopOnFailure: orchestratorStopOnFailure);

        var alerts = generator.Generate(config).Select(t => t.Raw).ToList();
        return new InMemorySiemConnector("simulator", alerts);
    });
}

services.AddSingleton(_ => new OrchestratorConfig(
    Environment: "dev",
    DryRun: orchestratorDryRun,
    ActionTimeout: TimeSpan.FromSeconds(orchestratorActionTimeoutSeconds),
    StopOnFailure: orchestratorStopOnFailure));
services.AddSingleton<AgentOrchestrator>();

var provider = services.BuildServiceProvider();
var orchestrator = provider.GetRequiredService<AgentOrchestrator>();

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

// Count enrichment providers for startup banner
var enrichmentDir2 = Environment.GetEnvironmentVariable("ENRICHMENT_DATA_PATH") ?? Path.Combine("data", "enrichment");
var enrichmentCount = new[] { "assets.json", "threat_intel.json", "identities.json" }
    .Count(f => File.Exists(Path.Combine(enrichmentDir2, f)));

var activeProfile = Environment.GetEnvironmentVariable("INTEL_ACTIVE_PROFILE")
    ?? Environment.GetEnvironmentVariable("INTEL_MODEL_PROFILE")
    ?? "default";

if (!string.IsNullOrWhiteSpace(webhookUrl))
{
    ProgramHelpers.PrintStartupBanner(
        mode: "webhook",
        webhookUrl: webhookUrl,
        intelligenceUrl: intelligence.BaseUrl,
        modelProfile: activeProfile,
        enrichmentProviders: enrichmentCount,
        dryRun: orchestratorDryRun,
        date: DateTimeOffset.UtcNow.ToString("yyyy-MM-dd"));

    var listener = new WebhookAlertListener(webhookUrl);
    Console.WriteLine($"  Listening on {webhookUrl}  (press Ctrl+C to stop and print summary)");
    Console.WriteLine();
    await listener.RunAsync(alert => orchestrator.HandleAlertAsync(alert, cts.Token), cts.Token);
    orchestrator.PrintExecutiveSummary();
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
