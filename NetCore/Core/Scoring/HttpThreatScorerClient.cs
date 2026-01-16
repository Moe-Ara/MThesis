using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Core.Scoring;

public sealed class HttpThreatScorerClient : IThreatScorer
{
    private readonly ThreatScorerApiOptions _options;
    private readonly HttpClient _http;
    private readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web);

    public HttpThreatScorerClient(ThreatScorerApiOptions options, HttpClient? httpClient = null)
    {
        if (options is null) throw new ArgumentNullException(nameof(options));
        _options = ApplyEnvOverrides(options);
        _http = httpClient ?? new HttpClient();
        if (_options.TimeoutSeconds > 0)
            _http.Timeout = TimeSpan.FromSeconds(_options.TimeoutSeconds);
    }

    public ThreatAssessment Score(EnrichedAlert enrichedAlert)
    {
        if (enrichedAlert is null) throw new ArgumentNullException(nameof(enrichedAlert));

        var correlationId = ResolveCorrelationId(enrichedAlert);
        var url = $"{_options.BaseUrl.TrimEnd('/')}/v1/score";

        var payload = new
        {
            correlationId,
            alert = new
            {
                sourceSiem = enrichedAlert.Base.SourceSiem,
                alertId = enrichedAlert.Base.AlertId,
                type = enrichedAlert.Base.AlertType,
                timestampUtc = enrichedAlert.Base.TimestampUtc.ToString("O"),
                entities = new
                {
                    hostId = enrichedAlert.Base.Entities.HostId,
                    username = enrichedAlert.Base.Entities.Username,
                    srcIp = enrichedAlert.Base.Entities.SrcIp,
                    fileHash = enrichedAlert.Base.Entities.FileHash
                },
                context = new
                {
                    environment = enrichedAlert.Context.Asset?.Environment ?? "unknown",
                    assetCriticality = enrichedAlert.Context.Asset?.Criticality ?? 0,
                    privileged = enrichedAlert.Context.Identity?.Privileged ?? false
                }
            }
        };

        try
        {
            var req = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new StringContent(JsonSerializer.Serialize(payload, _json), Encoding.UTF8, "application/json")
            };

            if (!string.IsNullOrWhiteSpace(_options.ApiKey))
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _options.ApiKey);

            using var resp = _http.Send(req);
            var body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();

            if (!resp.IsSuccessStatusCode)
                return Fallback();

            var parsed = JsonSerializer.Deserialize<ScorerResponse>(body, _json);
            if (parsed is null)
                return Fallback();

            return new ThreatAssessment(parsed.Confidence, parsed.Severity,
                parsed.Hypothesis ?? "scorer response", parsed.Evidence ?? new List<string>());
        }
        catch
        {
            return Fallback();
        }
    }

    public Explanation Explain(EnrichedAlert enrichedAlert)
    {
        var assessment = Score(enrichedAlert);
        return new Explanation(
            Summary: assessment.Hypothesis,
            Details: assessment.Evidence);
    }

    private static ThreatAssessment Fallback()
        => new(0.3, 30, "scorer unavailable", new List<string>());

    private static string ResolveCorrelationId(EnrichedAlert alert)
    {
        if (alert.Context.Tags is not null &&
            alert.Context.Tags.TryGetValue("correlation_id", out var id) &&
            !string.IsNullOrWhiteSpace(id))
        {
            return id;
        }

        return alert.Base.AlertId;
    }

    private static ThreatScorerApiOptions ApplyEnvOverrides(ThreatScorerApiOptions options)
    {
        var baseUrl = Environment.GetEnvironmentVariable("THREAT_SCORER_BASEURL") ?? options.BaseUrl;
        var apiKey = Environment.GetEnvironmentVariable("THREAT_SCORER_API_KEY") ?? options.ApiKey;
        var timeoutRaw = Environment.GetEnvironmentVariable("THREAT_SCORER_TIMEOUT_SECONDS");
        var timeout = options.TimeoutSeconds;
        if (int.TryParse(timeoutRaw, out var parsed))
            timeout = parsed;

        return new ThreatScorerApiOptions(baseUrl, apiKey, timeout);
    }

    private sealed record ScorerResponse(
        int Severity,
        double Confidence,
        string? Hypothesis,
        List<string>? Evidence
    );
}
