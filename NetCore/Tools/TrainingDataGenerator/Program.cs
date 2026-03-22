using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Core.NormalizationPipeline;
using Core.Planning;
using Core.Scoring;
using Core.Simulation;

var options = Options.Parse(Environment.GetCommandLineArgs());
Directory.CreateDirectory(options.OutputDir);

var generator = new ThreatGenerator();
var config = new ThreatGenConfig(
    Seed: options.Seed,
    Count: options.Count,
    Environment: options.Environment,
    DryRun: true,
    IncludeEdgeCases: options.IncludeEdgeCases,
    ScenarioWeights: new Dictionary<string, int>(),
    UsePythonScorer: false,
    ActionTimeout: TimeSpan.FromSeconds(1),
    StopOnFailure: false);

var threats = generator.Generate(config);

var normalization = new NormalizationPipeline(
    new SimulationMappingRegistry(),
    new BasicAlertValidator(),
    Array.Empty<Core.Interfaces.IEnrichmentProvider>(),
    new DefaultEnrichmentMerger());

var scorer = new StubThreatScorer();
var planner = new Planner(
    ActionCatalogDefaults.CreateDefault(),
    new BasicStrategySelector(),
    new BasicActionSelector(),
    new BasicRiskEstimator(),
    new BasicRollbackBuilder(),
    new BasicActionNormalizer(),
    new BasicActionSanitizer());

var splits = SplitPlan.Build(options);
var scoringWriters = splits.CreateWriters(options.OutputDir, "scoring");
var planningWriters = splits.CreateWriters(options.OutputDir, "planning");
var hfWriters = options.ExportHf ? splits.CreateWriters(options.OutputDir, "hf") : new Dictionary<string, StreamWriter>();
var alpacaWriters = options.ExportAlpaca ? splits.CreateWriters(options.OutputDir, "alpaca") : new Dictionary<string, StreamWriter>();

var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web)
{
    DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
};

for (var i = 0; i < threats.Count; i++)
{
    var threat = threats[i];
    var enriched = normalization.ProcessAsync(threat.Raw).GetAwaiter().GetResult();
    var assessment = scorer.Score(enriched);

    var planningContext = new PlanningContext(
        Environment: options.Environment,
        DryRun: true,
        Catalog: ActionCatalogDefaults.CreateDefault(),
        NowUtc: DateTimeOffset.UtcNow);

    var plan = planner.Plan(enriched, assessment, planningContext);

    var alertPayload = BuildAlertPayload(enriched);
    if (options.AugmentRate > 0 && options.Random.NextDouble() < options.AugmentRate)
        alertPayload = AugmentAlertPayload(alertPayload, options.Random, options.AugmentNoiseFields);

    var scoringOutput = NormalizeScoringOutput(new Dictionary<string, object?>
    {
        ["severity"] = assessment.Severity,
        ["confidence"] = assessment.Confidence,
        ["hypothesis"] = assessment.Hypothesis,
        ["evidence"] = assessment.Evidence
    });

    var planOutput = BuildPlanPayload(plan);
    if (!ValidatePlanPayload(planOutput, out _))
        planOutput = BuildPlanPayload(plan);

    var scoringRecord = BuildRecord(
        system: Prompts.ScorerSystem,
        user: $"Alert:\n{JsonSerializer.Serialize(alertPayload, jsonOptions)}",
        assistant: JsonSerializer.Serialize(scoringOutput, jsonOptions),
        metadata: new Dictionary<string, object?>
        {
            ["scenario"] = threat.ScenarioType,
            ["scenarioId"] = threat.ScenarioId
        },
        input: new Dictionary<string, object?> { ["alert"] = alertPayload },
        output: scoringOutput,
        format: options.Format
    );

    var planningRecord = BuildRecord(
        system: Prompts.PlannerSystem,
        user: $"Alert:\n{JsonSerializer.Serialize(alertPayload, jsonOptions)}\n\nAssessment:\n{JsonSerializer.Serialize(scoringOutput, jsonOptions)}",
        assistant: JsonSerializer.Serialize(planOutput, jsonOptions),
        metadata: new Dictionary<string, object?>
        {
            ["scenario"] = threat.ScenarioType,
            ["scenarioId"] = threat.ScenarioId
        },
        input: new Dictionary<string, object?>
        {
            ["alert"] = alertPayload,
            ["assessment"] = scoringOutput
        },
        output: planOutput,
        format: options.Format
    );

    var split = splits.Resolve(i);
    scoringWriters[split].WriteLine(JsonSerializer.Serialize(scoringRecord, jsonOptions));
    planningWriters[split].WriteLine(JsonSerializer.Serialize(planningRecord, jsonOptions));

    if (options.ExportHf)
    {
        hfWriters[split].WriteLine(JsonSerializer.Serialize(BuildHfRecord(scoringRecord), jsonOptions));
        hfWriters[split].WriteLine(JsonSerializer.Serialize(BuildHfRecord(planningRecord), jsonOptions));
    }

    if (options.ExportAlpaca)
    {
        alpacaWriters[split].WriteLine(JsonSerializer.Serialize(BuildAlpacaRecord(scoringRecord), jsonOptions));
        alpacaWriters[split].WriteLine(JsonSerializer.Serialize(BuildAlpacaRecord(planningRecord), jsonOptions));
    }
}

if (options.RealAlertsPath is not null)
{
    Console.WriteLine($"Augmenting with real alerts from {options.RealAlertsPath}");
    foreach (var alert in LoadRealAlerts(options.RealAlertsPath))
    {
        var enriched = normalization.ProcessAsync(alert).GetAwaiter().GetResult();
        var assessment = scorer.Score(enriched);
        var planningContext = new PlanningContext(
            Environment: options.Environment,
            DryRun: true,
            Catalog: ActionCatalogDefaults.CreateDefault(),
            NowUtc: DateTimeOffset.UtcNow);
        var plan = planner.Plan(enriched, assessment, planningContext);

        var alertPayload = BuildAlertPayload(enriched);
        if (options.AugmentRate > 0 && options.Random.NextDouble() < options.AugmentRate)
            alertPayload = AugmentAlertPayload(alertPayload, options.Random, options.AugmentNoiseFields);

        var scoringOutput = NormalizeScoringOutput(new Dictionary<string, object?>
        {
            ["severity"] = assessment.Severity,
            ["confidence"] = assessment.Confidence,
            ["hypothesis"] = assessment.Hypothesis,
            ["evidence"] = assessment.Evidence
        });

        var planOutput = BuildPlanPayload(plan);
        if (!ValidatePlanPayload(planOutput, out _))
            planOutput = BuildPlanPayload(plan);

        var scoringRecord = BuildRecord(
            system: Prompts.ScorerSystem,
            user: $"Alert:\n{JsonSerializer.Serialize(alertPayload, jsonOptions)}",
            assistant: JsonSerializer.Serialize(scoringOutput, jsonOptions),
            metadata: new Dictionary<string, object?>
            {
                ["scenario"] = "real",
                ["scenarioId"] = enriched.Base.AlertId
            },
            input: new Dictionary<string, object?> { ["alert"] = alertPayload },
            output: scoringOutput,
            format: options.Format
        );

        var planningRecord = BuildRecord(
            system: Prompts.PlannerSystem,
            user: $"Alert:\n{JsonSerializer.Serialize(alertPayload, jsonOptions)}\n\nAssessment:\n{JsonSerializer.Serialize(scoringOutput, jsonOptions)}",
            assistant: JsonSerializer.Serialize(planOutput, jsonOptions),
            metadata: new Dictionary<string, object?>
            {
                ["scenario"] = "real",
                ["scenarioId"] = enriched.Base.AlertId
            },
            input: new Dictionary<string, object?>
            {
                ["alert"] = alertPayload,
                ["assessment"] = scoringOutput
            },
            output: planOutput,
            format: options.Format
        );

        var split = "train";
        scoringWriters[split].WriteLine(JsonSerializer.Serialize(scoringRecord, jsonOptions));
        planningWriters[split].WriteLine(JsonSerializer.Serialize(planningRecord, jsonOptions));

        if (options.ExportHf)
        {
            hfWriters[split].WriteLine(JsonSerializer.Serialize(BuildHfRecord(scoringRecord), jsonOptions));
            hfWriters[split].WriteLine(JsonSerializer.Serialize(BuildHfRecord(planningRecord), jsonOptions));
        }

        if (options.ExportAlpaca)
        {
            alpacaWriters[split].WriteLine(JsonSerializer.Serialize(BuildAlpacaRecord(scoringRecord), jsonOptions));
            alpacaWriters[split].WriteLine(JsonSerializer.Serialize(BuildAlpacaRecord(planningRecord), jsonOptions));
        }
    }
}

foreach (var writer in scoringWriters.Values)
    writer.Dispose();
foreach (var writer in planningWriters.Values)
    writer.Dispose();
foreach (var writer in hfWriters.Values)
    writer.Dispose();
foreach (var writer in alpacaWriters.Values)
    writer.Dispose();

Console.WriteLine($"Generated {options.Count} samples into {options.OutputDir}");


static Dictionary<string, object?> BuildAlertPayload(EnrichedAlert enriched)
{
    var entities = enriched.Base.Entities;
    var context = enriched.Context;

    var entityMap = new Dictionary<string, object?>
    {
        ["hostname"] = entities.Hostname,
        ["hostId"] = entities.HostId,
        ["username"] = entities.Username,
        ["userId"] = entities.UserId,
        ["srcIp"] = entities.SrcIp,
        ["dstIp"] = entities.DstIp,
        ["domain"] = entities.Domain,
        ["processName"] = entities.ProcessName,
        ["processPath"] = entities.ProcessPath,
        ["fileHash"] = entities.FileHash
    };

    var contextMap = new Dictionary<string, object?>
    {
        ["environment"] = context.Asset?.Environment,
        ["assetCriticality"] = context.Asset?.Criticality ?? 0,
        ["privileged"] = context.Identity?.Privileged ?? false
    };

    return new Dictionary<string, object?>
    {
        ["sourceSiem"] = enriched.Base.SourceSiem,
        ["alertId"] = enriched.Base.AlertId,
        ["type"] = enriched.Base.AlertType,
        ["ruleName"] = enriched.Base.RuleName,
        ["timestampUtc"] = enriched.Base.TimestampUtc.ToString("O"),
        ["severity"] = enriched.Base.Severity,
        ["entities"] = entityMap,
        ["context"] = contextMap
    };
}

static Dictionary<string, object?> BuildPlanPayload(DecisionPlan plan)
{
    return new Dictionary<string, object?>
    {
        ["planId"] = plan.PlanId,
        ["strategy"] = plan.Strategy.ToString(),
        ["priority"] = plan.Priority,
        ["summary"] = plan.Summary,
        ["actions"] = plan.Actions.Select(BuildActionPayload).ToList(),
        ["rollbackActions"] = plan.RollbackActions.Select(BuildActionPayload).ToList(),
        ["rationale"] = plan.Rationale,
        ["tags"] = plan.Tags
    };
}

static Dictionary<string, object?> BuildActionPayload(PlannedAction action)
{
    var payload = new Dictionary<string, object?>
    {
        ["actionId"] = action.ActionId,
        ["type"] = action.Type.ToString(),
        ["risk"] = action.Risk,
        ["expectedImpact"] = action.ExpectedImpact,
        ["reversible"] = action.Reversible,
        ["parameters"] = action.Parameters,
        ["rationale"] = action.Rationale
    };
    if (action.Duration.HasValue)
        payload["durationSeconds"] = (int)action.Duration.Value.TotalSeconds;
    return payload;
}

static Dictionary<string, object?> BuildRecord(
    string system,
    string user,
    string assistant,
    Dictionary<string, object?> metadata,
    Dictionary<string, object?> input,
    Dictionary<string, object?> output,
    DatasetFormat format)
{
    var record = new Dictionary<string, object?>
    {
        ["metadata"] = metadata
    };

    if (format is DatasetFormat.Chat or DatasetFormat.Both)
    {
        record["messages"] = new[]
        {
            new Dictionary<string, object?> { ["role"] = "system", ["content"] = system },
            new Dictionary<string, object?> { ["role"] = "user", ["content"] = user },
            new Dictionary<string, object?> { ["role"] = "assistant", ["content"] = assistant }
        };
    }

    if (format is DatasetFormat.IO or DatasetFormat.Both)
    {
        record["input"] = input;
        record["output"] = output;
    }

    return record;
}

static Dictionary<string, object?> BuildHfRecord(Dictionary<string, object?> record)
{
    if (!record.TryGetValue("messages", out var messagesObj))
        return record;
    return new Dictionary<string, object?>
    {
        ["messages"] = messagesObj
    };
}

static Dictionary<string, object?> BuildAlpacaRecord(Dictionary<string, object?> record)
{
    var instruction = string.Empty;
    var input = string.Empty;
    var output = string.Empty;

    if (record.TryGetValue("messages", out var messagesObj) && messagesObj is IEnumerable<object> messages)
    {
        foreach (var msg in messages)
        {
            if (msg is not Dictionary<string, object?> message)
                continue;
            var role = message.GetValueOrDefault("role") as string;
            var content = message.GetValueOrDefault("content") as string ?? string.Empty;
            if (role == "system")
                instruction = content;
            else if (role == "user")
                input = content;
            else if (role == "assistant")
                output = content;
        }
    }

    return new Dictionary<string, object?>
    {
        ["instruction"] = instruction,
        ["input"] = input,
        ["output"] = output
    };
}

static Dictionary<string, object?> AugmentAlertPayload(
    Dictionary<string, object?> alert,
    Random rng,
    int noiseFields)
{
    var augmented = new Dictionary<string, object?>(alert);

    if (augmented.TryGetValue("entities", out var entitiesObj) && entitiesObj is Dictionary<string, object?> entities)
    {
        foreach (var key in entities.Keys.ToList())
        {
            if (rng.NextDouble() < 0.2)
                entities[key] = null;
        }
    }

    if (augmented.TryGetValue("context", out var contextObj) && contextObj is Dictionary<string, object?> context)
    {
        if (rng.NextDouble() < 0.15 && context.TryGetValue("assetCriticality", out var value))
        {
            var current = value is int v ? v : 0;
            context["assetCriticality"] = Math.Max(0, current + rng.Next(-1, 2));
        }
    }

    for (var i = 0; i < noiseFields; i++)
    {
        if (rng.NextDouble() < 0.3)
            augmented[$"noise_{i}"] = rng.Next(0, 1000);
    }

    return augmented;
}

static Dictionary<string, object?> NormalizeScoringOutput(Dictionary<string, object?> output)
{
    if (output.TryGetValue("severity", out var severityObj) && severityObj is int severity)
        output["severity"] = Math.Clamp(severity, 0, 100);
    if (output.TryGetValue("confidence", out var confObj) && confObj is double conf)
        output["confidence"] = Math.Clamp(conf, 0.0, 1.0);
    return output;
}

static bool ValidatePlanPayload(Dictionary<string, object?> plan, out List<string> errors)
{
    errors = new List<string>();
    if (!plan.ContainsKey("planId"))
        errors.Add("missing planId");
    if (!plan.TryGetValue("strategy", out var strategyObj) || strategyObj is not string strategy ||
        !Enum.TryParse<PlanStrategy>(strategy, out _))
        errors.Add("invalid strategy");
    if (!plan.TryGetValue("actions", out var actionsObj) || actionsObj is not IEnumerable<object> actions)
    {
        errors.Add("missing actions");
        return errors.Count == 0;
    }

    foreach (var item in actions)
    {
        if (item is not Dictionary<string, object?> action)
        {
            errors.Add("invalid action object");
            continue;
        }
        if (!action.TryGetValue("type", out var typeObj) || typeObj is not string type ||
            !Enum.TryParse<ActionType>(type, out _))
            errors.Add("invalid action type");
        if (!action.ContainsKey("parameters"))
            errors.Add("missing parameters");
        if (!action.ContainsKey("rationale"))
            errors.Add("missing rationale");
    }

    return errors.Count == 0;
}

static IEnumerable<RawAlert> LoadRealAlerts(string path)
{
    if (!File.Exists(path))
        yield break;

    foreach (var line in File.ReadLines(path))
    {
        if (string.IsNullOrWhiteSpace(line))
            continue;
        RawAlert? raw = null;
        try
        {
            var json = JsonSerializer.Deserialize<JsonElement>(line);
            if (json.ValueKind == JsonValueKind.Undefined)
                continue;
            raw = new RawAlert
            {
                AlertId = Guid.NewGuid().ToString("N"),
                SiemName = "wazuh",
                TimestampUtc = DateTimeOffset.UtcNow,
                AlertType = json.TryGetProperty("rule", out var rule) && rule.TryGetProperty("id", out var id)
                    ? id.ToString()
                    : "unknown",
                RuleName = json.TryGetProperty("rule", out var rule2) && rule2.TryGetProperty("description", out var desc)
                    ? desc.GetString()
                    : null,
                OriginalSeverity = json.TryGetProperty("rule", out var rule3) && rule3.TryGetProperty("level", out var level) && level.TryGetInt32(out var sev)
                    ? sev
                    : null,
                Payload = json
            };
        }
        catch
        {
            // ignore malformed line
        }
        if (raw is not null)
            yield return raw;
    }
}

static class Prompts
{
    public const string ScorerSystem =
        "You are a SOC threat scoring assistant. Return JSON with fields: severity (0-100 int), " +
        "confidence (0-1 float), hypothesis (string), evidence (array of strings). Be concise and deterministic.";

    public const string PlannerSystem =
        "You are a SOC response planner. Return ONLY a JSON object with fields: " +
        "planId, strategy, priority, summary, actions, rollbackActions, rationale, tags. " +
        "Each action must include type, risk, expectedImpact, reversible, parameters, rationale.";
}

sealed record Options(
    int Count,
    int Seed,
    string Environment,
    bool IncludeEdgeCases,
    string OutputDir,
    double TrainRatio,
    double ValRatio,
    double TestRatio,
    DatasetFormat Format,
    double AugmentRate,
    int AugmentNoiseFields,
    Random Random,
    bool ExportHf,
    bool ExportAlpaca,
    string? RealAlertsPath)
{
    public static Options Parse(string[] args)
    {
        var count = GetInt(args, "--count", 50000);
        var seed = GetInt(args, "--seed", 123);
        var environment = GetString(args, "--environment", "dev");
        var includeEdgeCases = GetFlag(args, "--include-edge");
        var outputDir = GetString(args, "--output-dir", Path.Combine("data", "training"));
        var split = GetString(args, "--split", "0.9,0.05,0.05");
        var formatRaw = GetString(args, "--format", "both");
        var format = DatasetFormatExtensions.Parse(formatRaw);
        var augmentRate = GetDouble(args, "--augment-rate", 0.15);
        var augmentNoise = GetInt(args, "--augment-noise", 2);
        var exportHf = GetFlag(args, "--export-hf");
        var exportAlpaca = GetFlag(args, "--export-alpaca");
        var realAlertsPath = GetString(args, "--real-alerts", string.Empty);
        var ratios = split.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(s => double.TryParse(s, out var v) ? v : 0.0)
            .ToArray();
        var train = ratios.Length > 0 ? ratios[0] : 1.0;
        var val = ratios.Length > 1 ? ratios[1] : 0.0;
        var test = ratios.Length > 2 ? ratios[2] : 0.0;
        var sum = train + val + test;
        if (sum <= 0)
        {
            train = 1.0;
            val = 0.0;
            test = 0.0;
        }
        else
        {
            train /= sum;
            val /= sum;
            test /= sum;
        }

        return new Options(
            count,
            seed,
            environment,
            includeEdgeCases,
            outputDir,
            train,
            val,
            test,
            format,
            augmentRate,
            augmentNoise,
            new Random(seed),
            exportHf,
            exportAlpaca,
            string.IsNullOrWhiteSpace(realAlertsPath) ? null : realAlertsPath);
    }

    private static int GetInt(string[] args, string key, int fallback)
    {
        var idx = Array.IndexOf(args, key);
        if (idx >= 0 && idx + 1 < args.Length && int.TryParse(args[idx + 1], out var value))
            return value;
        return fallback;
    }

    private static string GetString(string[] args, string key, string fallback)
    {
        var idx = Array.IndexOf(args, key);
        if (idx >= 0 && idx + 1 < args.Length)
            return args[idx + 1];
        return fallback;
    }

    private static bool GetFlag(string[] args, string key)
        => args.Contains(key, StringComparer.OrdinalIgnoreCase);

    private static double GetDouble(string[] args, string key, double fallback)
    {
        var idx = Array.IndexOf(args, key);
        if (idx >= 0 && idx + 1 < args.Length && double.TryParse(args[idx + 1], out var value))
            return value;
        return fallback;
    }
}

enum DatasetFormat
{
    Chat,
    IO,
    Both
}

static class DatasetFormatExtensions
{
    public static DatasetFormat Parse(string raw)
    {
        return raw.ToLowerInvariant() switch
        {
            "chat" => DatasetFormat.Chat,
            "io" => DatasetFormat.IO,
            "both" => DatasetFormat.Both,
            _ => DatasetFormat.Both
        };
    }
}

sealed class SplitPlan
{
    private readonly int _train;
    private readonly int _val;
    private readonly int _test;

    private SplitPlan(int train, int val, int test)
    {
        _train = train;
        _val = val;
        _test = test;
    }

    public static SplitPlan Build(Options options)
    {
        var train = (int)Math.Round(options.Count * options.TrainRatio);
        var val = (int)Math.Round(options.Count * options.ValRatio);
        var test = options.Count - train - val;
        if (test < 0)
            test = 0;
        return new SplitPlan(train, val, test);
    }

    public string Resolve(int index)
    {
        if (index < _train)
            return "train";
        if (index < _train + _val)
            return "val";
        return "test";
    }

    public Dictionary<string, StreamWriter> CreateWriters(string outputDir, string prefix)
    {
        var writers = new Dictionary<string, StreamWriter>();
        if (_train > 0)
            writers["train"] = new StreamWriter(Path.Combine(outputDir, $"{prefix}_train.jsonl"));
        if (_val > 0)
            writers["val"] = new StreamWriter(Path.Combine(outputDir, $"{prefix}_val.jsonl"));
        if (_test > 0)
            writers["test"] = new StreamWriter(Path.Combine(outputDir, $"{prefix}_test.jsonl"));
        return writers;
    }
}
