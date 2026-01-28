using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace Core.Planning;

public sealed class HttpPlannerClient
{
    private readonly HttpPlannerOptions _options;
    private readonly HttpClient _http;
    private readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web);

    public HttpPlannerClient(HttpPlannerOptions options, HttpClient? httpClient = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _http = httpClient ?? new HttpClient();
        if (_options.TimeoutSeconds > 0)
            _http.Timeout = TimeSpan.FromSeconds(_options.TimeoutSeconds);
    }

    public DecisionPlan? Plan(EnrichedAlert alert, ThreatAssessment assessment, PlanningContext ctx)
    {
        if (alert is null) throw new ArgumentNullException(nameof(alert));
        if (assessment is null) throw new ArgumentNullException(nameof(assessment));
        if (ctx is null) throw new ArgumentNullException(nameof(ctx));

        EnsureConfigured();

        var url = CombineUrl(_options.BaseUrl, _options.Endpoint);
        var payload = new
        {
            alert = new
            {
                sourceSiem = alert.Base.SourceSiem,
                alertId = alert.Base.AlertId,
                type = alert.Base.AlertType,
                ruleName = alert.Base.RuleName,
                timestampUtc = alert.Base.TimestampUtc.ToString("O"),
                severity = alert.Base.Severity,
                entities = alert.Base.Entities,
                context = alert.Context
            },
            assessment = new
            {
                confidence = assessment.Confidence,
                severity = assessment.Severity,
                hypothesis = assessment.Hypothesis,
                evidence = assessment.Evidence,
                recommendedActions = assessment.RecommendedActions
            },
            planning = new
            {
                environment = ctx.Environment,
                dryRun = ctx.DryRun,
                nowUtc = ctx.NowUtc.ToString("O")
            }
        };

        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new StringContent(JsonSerializer.Serialize(payload, _json), Encoding.UTF8, "application/json")
            };
            ApplyAuth(req);

            using var resp = _http.Send(req);
            var body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            if (!resp.IsSuccessStatusCode || string.IsNullOrWhiteSpace(body))
                return null;

            return ParseDecisionPlan(body) ?? null;
        }
        catch
        {
            return null;
        }
    }

    private void EnsureConfigured()
    {
        if (string.IsNullOrWhiteSpace(_options.BaseUrl))
            throw new InvalidOperationException("Planner API BaseUrl is required.");
    }

    private void ApplyAuth(HttpRequestMessage request)
    {
        if (string.IsNullOrWhiteSpace(_options.ApiKey))
            return;

        var header = _options.ApiKeyHeaderName;
        var value = _options.ApiKey!;
        if (!string.IsNullOrWhiteSpace(_options.ApiKeyPrefix))
            value = $"{_options.ApiKeyPrefix} {value}";

        if (request.Headers.Contains(header))
            request.Headers.Remove(header);
        request.Headers.Add(header, value);
    }

    private static string CombineUrl(string baseUrl, string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return baseUrl.TrimEnd('/');
        if (path.StartsWith("/", StringComparison.Ordinal))
            return baseUrl.TrimEnd('/') + path;
        return baseUrl.TrimEnd('/') + "/" + path;
    }

    private DecisionPlan? ParseDecisionPlan(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (root.TryGetProperty("plan", out var plan))
            root = plan;

        var planId = GetString(root, "planId") ?? Guid.NewGuid().ToString("N");
        var strategy = ParseStrategy(GetString(root, "strategy"));
        var priority = GetInt(root, "priority") ?? 0;
        var summary = GetString(root, "summary") ?? string.Empty;
        var actions = ParseActions(root, "actions");
        var rollback = ParseActions(root, "rollbackActions");
        var rationale = ParseStringList(root, "rationale");
        var tags = ParseStringMap(root, "tags");

        if (actions.Count == 0)
            return null;

        return new DecisionPlan(planId, strategy, priority, summary, actions, rollback, rationale, tags);
    }

    private static IReadOnlyList<PlannedAction> ParseActions(JsonElement root, string property)
    {
        var list = new List<PlannedAction>();
        if (!root.TryGetProperty(property, out var items) || items.ValueKind != JsonValueKind.Array)
            return list;

        foreach (var item in items.EnumerateArray())
        {
            var typeRaw = GetString(item, "type");
            if (!Enum.TryParse<ActionType>(typeRaw, true, out var type))
                continue;

            var parameters = ParseStringMap(item, "parameters") ?? new Dictionary<string, string>();
            var actionId = GetString(item, "actionId") ?? ActionIdFactory.Create(type, parameters);
            var risk = GetInt(item, "risk") ?? 0;
            var impact = GetInt(item, "expectedImpact") ?? 0;
            var reversible = GetBool(item, "reversible") ?? false;
            var duration = GetInt(item, "durationSeconds");
            var rationale = GetString(item, "rationale") ?? string.Empty;

            list.Add(new PlannedAction(
                ActionId: actionId,
                Type: type,
                Risk: risk,
                ExpectedImpact: impact,
                Reversible: reversible,
                Duration: duration.HasValue ? TimeSpan.FromSeconds(duration.Value) : null,
                Parameters: parameters,
                Rationale: rationale));
        }

        return list;
    }

    private static IReadOnlyList<string> ParseStringList(JsonElement root, string property)
    {
        if (!root.TryGetProperty(property, out var items) || items.ValueKind != JsonValueKind.Array)
            return Array.Empty<string>();

        var list = new List<string>();
        foreach (var item in items.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String)
                list.Add(item.GetString() ?? string.Empty);
            else
                list.Add(item.ToString());
        }

        return list;
    }

    private static IReadOnlyDictionary<string, string>? ParseStringMap(JsonElement root, string property)
    {
        if (!root.TryGetProperty(property, out var obj) || obj.ValueKind != JsonValueKind.Object)
            return null;

        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var prop in obj.EnumerateObject())
            map[prop.Name] = prop.Value.ValueKind == JsonValueKind.String ? prop.Value.GetString() ?? string.Empty : prop.Value.ToString();
        return map;
    }

    private static string? GetString(JsonElement root, string property)
    {
        if (!root.TryGetProperty(property, out var value))
            return null;
        return value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString();
    }

    private static int? GetInt(JsonElement root, string property)
    {
        if (!root.TryGetProperty(property, out var value))
            return null;
        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var parsed))
            return parsed;
        if (int.TryParse(value.ToString(), out parsed))
            return parsed;
        return null;
    }

    private static bool? GetBool(JsonElement root, string property)
    {
        if (!root.TryGetProperty(property, out var value))
            return null;
        if (value.ValueKind == JsonValueKind.True) return true;
        if (value.ValueKind == JsonValueKind.False) return false;
        if (bool.TryParse(value.ToString(), out var parsed))
            return parsed;
        return null;
    }

    private static PlanStrategy ParseStrategy(string? value)
        => Enum.TryParse<PlanStrategy>(value, true, out var parsed) ? parsed : PlanStrategy.NotifyOnly;
}
