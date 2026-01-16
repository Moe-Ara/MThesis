using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Core.Execution;

public sealed class HttpFirewallExecutor : IActionExecutor
{
    private readonly FirewallApiOptions _options;
    private readonly HttpClient _http;
    private readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web);

    public string Name => "HttpFirewallExecutor";

    public HttpFirewallExecutor(FirewallApiOptions options, HttpClient? httpClient = null)
    {
        if (options is null) throw new ArgumentNullException(nameof(options));
        _options = ApplyEnvOverrides(options);
        _http = httpClient ?? new HttpClient();
        if (_options.TimeoutSeconds > 0)
            _http.Timeout = TimeSpan.FromSeconds(_options.TimeoutSeconds);
    }

    public bool CanExecute(ActionType type)
        => type is ActionType.BlockIp or ActionType.UnblockIp;

    public Task<FeasibilityResult> CheckAsync(PlannedAction action, ExecutionContext ctx, CancellationToken ct)
    {
        if (!TryGetIp(action, out _))
            return Task.FromResult(new FeasibilityResult(false, "Missing required parameter 'src_ip'."));

        return Task.FromResult(new FeasibilityResult(true, "Ready"));
    }

    public async Task<ExecutionOutcome> ExecuteAsync(PlannedAction action, ExecutionContext ctx, CancellationToken ct)
    {
        if (!TryGetIp(action, out var ip))
            return new ExecutionOutcome(false, "Missing required parameter 'src_ip'.");

        var endpoint = action.Type == ActionType.BlockIp ? "block-ip" : "unblock-ip";
        var url = $"{_options.BaseUrl.TrimEnd('/')}/v1/firewall/{endpoint}";

        var payload = new
        {
            correlationId = action.ActionId,
            ip,
            reason = action.Rationale,
            ttlSeconds = action.Duration?.TotalSeconds is > 0 ? (int)action.Duration.Value.TotalSeconds : 3600
        };

        var req = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(JsonSerializer.Serialize(payload, _json), Encoding.UTF8, "application/json")
        };

        if (!string.IsNullOrWhiteSpace(_options.ApiKey))
            req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _options.ApiKey);

        try
        {
            using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
            var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                return new ExecutionOutcome(false, $"Firewall API error: {(int)resp.StatusCode}");

            var parsed = JsonSerializer.Deserialize<FirewallResponse>(body, _json);
            if (parsed is null)
                return new ExecutionOutcome(false, "Firewall API response invalid.");

            return new ExecutionOutcome(parsed.Success, parsed.Message ?? "ok", parsed.ReferenceId);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new ExecutionOutcome(false, $"Firewall API call failed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static bool TryGetIp(PlannedAction action, out string ip)
    {
        ip = string.Empty;
        if (!action.Parameters.TryGetValue("src_ip", out var value) || string.IsNullOrWhiteSpace(value))
            return false;
        ip = value;
        return true;
    }

    private static FirewallApiOptions ApplyEnvOverrides(FirewallApiOptions options)
    {
        var baseUrl = Environment.GetEnvironmentVariable("FIREWALL_API_BASEURL") ?? options.BaseUrl;
        var apiKey = Environment.GetEnvironmentVariable("FIREWALL_API_KEY") ?? options.ApiKey;
        var timeoutRaw = Environment.GetEnvironmentVariable("FIREWALL_API_TIMEOUT_SECONDS");
        var timeout = options.TimeoutSeconds;
        if (int.TryParse(timeoutRaw, out var parsed))
            timeout = parsed;

        return new FirewallApiOptions(baseUrl, apiKey, timeout);
    }

    private sealed record FirewallResponse(
        bool Success,
        string? ReferenceId,
        string? Message
    );
}
