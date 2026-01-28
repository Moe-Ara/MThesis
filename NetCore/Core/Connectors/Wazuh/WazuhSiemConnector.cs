using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Core.Interfaces;

namespace Core.Connectors.Wazuh;

public sealed class WazuhSiemConnector : ISiemConnector
{
    private readonly WazuhApiOptions _options;
    private readonly HttpClient _http;
    private bool _connected;

    public WazuhSiemConnector(WazuhApiOptions options, HttpClient? httpClient = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _http = httpClient ?? new HttpClient();
        if (_options.TimeoutSeconds > 0)
            _http.Timeout = TimeSpan.FromSeconds(_options.TimeoutSeconds);

        Capabilities = new SiemConnectorCapabilities(
            SupportsAck: !string.IsNullOrWhiteSpace(_options.AckEndpointTemplate),
            SupportsSubscribe: false,
            SupportsPull: true);
    }

    public string Name => "wazuh";
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

    public async Task<PullResult<RawAlert>> PullAlertsAsync(PullRequest request, CancellationToken ct)
    {
        EnsureConfigured();
        var url = BuildAlertsUrl(request);

        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        ApplyAuth(req);

        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
            throw new InvalidOperationException($"Wazuh API error: {(int)resp.StatusCode}");

        if (string.IsNullOrWhiteSpace(body))
            return new PullResult<RawAlert>(Array.Empty<RawAlert>(), request.Cursor, false);

        var (alerts, nextCursor) = ParseAlerts(body);
        return new PullResult<RawAlert>(alerts, nextCursor, nextCursor is not null);
    }

    public async Task AckAsync(string alertId, AckStatus status, CancellationToken ct)
    {
        if (!Capabilities.SupportsAck)
            return;

        if (string.IsNullOrWhiteSpace(alertId))
            return;

        EnsureConfigured();

        var endpoint = _options.AckEndpointTemplate ?? string.Empty;
        var relative = endpoint.Replace("{alertId}", Uri.EscapeDataString(alertId));
        var url = CombineUrl(_options.BaseUrl, relative);

        var payload = new Dictionary<string, string>
        {
            ["status"] = status.ToString()
        };

        using var req = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
        };
        ApplyAuth(req);

        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        _ = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
    }

    public Task SubscribeAsync(SubscriptionRequest request, CancellationToken ct)
        => Task.CompletedTask;

    public Task UnsubscribeAsync(string subscriptionId, CancellationToken ct)
        => Task.CompletedTask;

    public Task<ConnectorHealth> GetHealthAsync(CancellationToken ct)
        => Task.FromResult(new ConnectorHealth(true, "ok", DateTimeOffset.UtcNow));

    private void EnsureConfigured()
    {
        if (string.IsNullOrWhiteSpace(_options.BaseUrl))
            throw new InvalidOperationException("Wazuh API BaseUrl is required.");
        if (string.IsNullOrWhiteSpace(_options.ApiKey))
            throw new InvalidOperationException("Wazuh API key is required.");
    }

    private string BuildAlertsUrl(PullRequest request)
    {
        var url = CombineUrl(_options.BaseUrl, _options.AlertsEndpoint);
        var query = new Dictionary<string, string>();

        if (request.Limit > 0)
            query[_options.LimitParamName] = request.Limit.ToString();
        if (request.SinceUtc.HasValue)
            query[_options.SinceParamName] = request.SinceUtc.Value.ToUnixTimeSeconds().ToString();
        if (!string.IsNullOrWhiteSpace(request.Cursor))
            query[_options.CursorParamName] = request.Cursor!;

        if (query.Count == 0)
            return url;

        var delimiter = url.Contains('?') ? "&" : "?";
        return url + delimiter + string.Join("&", query.Select(kv =>
            $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
    }

    private void ApplyAuth(HttpRequestMessage request)
    {
        var header = _options.ApiKeyHeaderName;
        if (string.IsNullOrWhiteSpace(header))
            return;

        var value = _options.ApiKey;
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

    private static (IReadOnlyList<RawAlert> Alerts, string? NextCursor) ParseAlerts(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var elements = ExtractAlertElements(root).ToList();
        var alerts = elements.Select(BuildRawAlert).ToList();
        var nextCursor = TryGetString(root, "cursor") ?? TryGetString(root, "next_cursor");
        return (alerts, nextCursor);
    }

    private static IEnumerable<JsonElement> ExtractAlertElements(JsonElement root)
    {
        if (root.ValueKind == JsonValueKind.Array)
            return root.EnumerateArray();

        if (root.ValueKind != JsonValueKind.Object)
            return new[] { root };

        if (root.TryGetProperty("data", out var data))
        {
            if (data.ValueKind == JsonValueKind.Object)
            {
                if (data.TryGetProperty("affected_items", out var affected) &&
                    affected.ValueKind == JsonValueKind.Array)
                {
                    return affected.EnumerateArray();
                }
                if (data.TryGetProperty("items", out var items) &&
                    items.ValueKind == JsonValueKind.Array)
                {
                    return items.EnumerateArray();
                }
            }
            if (data.ValueKind == JsonValueKind.Array)
                return data.EnumerateArray();
        }

        if (root.TryGetProperty("alerts", out var alerts) &&
            alerts.ValueKind == JsonValueKind.Array)
        {
            return alerts.EnumerateArray();
        }

        return new[] { root };
    }

    private static RawAlert BuildRawAlert(JsonElement element)
    {
        var alertId = TryGetString(element, "id")
                      ?? TryGetString(element, "_id")
                      ?? TryGetString(element, "alert_id")
                      ?? Guid.NewGuid().ToString("N");

        var timestamp = TryGetDateTime(element, "timestamp")
                        ?? TryGetDateTime(element, "@timestamp")
                        ?? DateTimeOffset.UtcNow;

        var ruleName = TryGetNestedString(element, "rule", "description")
                       ?? TryGetNestedString(element, "rule", "name");

        var ruleId = TryGetNestedString(element, "rule", "id");
        var alertType = TryGetString(element, "alert_type") ?? ruleId;

        var severity = TryGetNestedInt(element, "rule", "level");

        return new RawAlert
        {
            AlertId = alertId,
            SiemName = "wazuh",
            TimestampUtc = timestamp,
            RuleName = ruleName,
            AlertType = alertType,
            OriginalSeverity = severity,
            Payload = element.Clone()
        };
    }

    private static string? TryGetString(JsonElement element, string property)
    {
        if (element.ValueKind != JsonValueKind.Object)
            return null;
        if (!element.TryGetProperty(property, out var value))
            return null;
        return value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString();
    }

    private static string? TryGetNestedString(JsonElement element, string parent, string property)
    {
        if (element.ValueKind != JsonValueKind.Object)
            return null;
        if (!element.TryGetProperty(parent, out var obj))
            return null;
        return TryGetString(obj, property);
    }

    private static int? TryGetNestedInt(JsonElement element, string parent, string property)
    {
        if (element.ValueKind != JsonValueKind.Object)
            return null;
        if (!element.TryGetProperty(parent, out var obj))
            return null;
        if (!obj.TryGetProperty(property, out var value))
            return null;
        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var parsed))
            return parsed;
        if (int.TryParse(value.ToString(), out parsed))
            return parsed;
        return null;
    }

    private static DateTimeOffset? TryGetDateTime(JsonElement element, string property)
    {
        var raw = TryGetString(element, property);
        if (string.IsNullOrWhiteSpace(raw))
            return null;
        if (DateTimeOffset.TryParse(raw, out var parsed))
            return parsed;
        return null;
    }
}
