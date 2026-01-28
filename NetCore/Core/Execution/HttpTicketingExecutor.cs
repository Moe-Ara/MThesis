using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Core.Execution;

public sealed class HttpTicketingExecutor : IActionExecutor
{
    private readonly TicketingApiOptions _options;
    private readonly HttpClient _http;
    private readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web);

    public string Name => "HttpTicketingExecutor";

    public HttpTicketingExecutor(TicketingApiOptions options, HttpClient? httpClient = null)
    {
        if (options is null) throw new ArgumentNullException(nameof(options));
        _options = ApplyEnvOverrides(options);
        _http = httpClient ?? new HttpClient();
        if (_options.TimeoutSeconds > 0)
            _http.Timeout = TimeSpan.FromSeconds(_options.TimeoutSeconds);
    }

    public bool CanExecute(ActionType type) => type == ActionType.OpenTicket;

    public Task<FeasibilityResult> CheckAsync(PlannedAction action, ExecutionContext ctx, CancellationToken ct)
        => Task.FromResult(new FeasibilityResult(true, "Ready"));

    public async Task<ExecutionOutcome> ExecuteAsync(PlannedAction action, ExecutionContext ctx, CancellationToken ct)
    {
        var url = CombineUrl(_options.BaseUrl, _options.Endpoint);
        var payload = new
        {
            correlationId = action.ActionId,
            title = ResolveTitle(action),
            description = ResolveDescription(action),
            parameters = action.Parameters,
            rationale = action.Rationale,
            environment = ctx.Environment
        };

        using var req = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(JsonSerializer.Serialize(payload, _json), Encoding.UTF8, "application/json")
        };
        ApplyAuth(req);

        try
        {
            using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
            var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                return new ExecutionOutcome(false, $"Ticketing API error: {(int)resp.StatusCode}");

            var parsed = JsonSerializer.Deserialize<ApiResponse>(body, _json);
            if (parsed is null)
                return new ExecutionOutcome(false, "Ticketing API response invalid.");

            return new ExecutionOutcome(parsed.Success, parsed.Message ?? "ok", parsed.ReferenceId);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new ExecutionOutcome(false, $"Ticketing API call failed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static string ResolveTitle(PlannedAction action)
    {
        if (action.Parameters.TryGetValue("title", out var title) && !string.IsNullOrWhiteSpace(title))
            return title;
        return $"Security ticket: {action.Type}";
    }

    private static string ResolveDescription(PlannedAction action)
    {
        if (action.Parameters.TryGetValue("description", out var desc) && !string.IsNullOrWhiteSpace(desc))
            return desc;
        return action.Rationale;
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

    private static TicketingApiOptions ApplyEnvOverrides(TicketingApiOptions options)
    {
        var baseUrl = Environment.GetEnvironmentVariable("TICKETING_API_BASEURL") ?? options.BaseUrl;
        var apiKey = Environment.GetEnvironmentVariable("TICKETING_API_KEY") ?? options.ApiKey;
        var endpoint = Environment.GetEnvironmentVariable("TICKETING_API_ENDPOINT") ?? options.Endpoint;
        var header = Environment.GetEnvironmentVariable("TICKETING_API_KEY_HEADER") ?? options.ApiKeyHeaderName;
        var prefix = Environment.GetEnvironmentVariable("TICKETING_API_KEY_PREFIX") ?? options.ApiKeyPrefix;
        var timeoutRaw = Environment.GetEnvironmentVariable("TICKETING_API_TIMEOUT_SECONDS");
        var timeout = options.TimeoutSeconds;
        if (int.TryParse(timeoutRaw, out var parsed))
            timeout = parsed;

        return new TicketingApiOptions(baseUrl, apiKey, endpoint, header, prefix, timeout);
    }

    private sealed record ApiResponse(
        bool Success,
        string? ReferenceId,
        string? Message
    );
}
