using System;

namespace Core.Connectors.Wazuh;

public sealed record WazuhApiOptions(
    string BaseUrl,
    string ApiKey,
    string AlertsEndpoint = "/alerts",
    string? AckEndpointTemplate = null,
    string ApiKeyHeaderName = "Authorization",
    string ApiKeyPrefix = "Bearer",
    string LimitParamName = "limit",
    string SinceParamName = "from",
    string CursorParamName = "cursor",
    int TimeoutSeconds = 30)
{
    public static WazuhApiOptions FromEnvironment()
    {
        var baseUrl = Environment.GetEnvironmentVariable("WAZUH_API_BASEURL") ?? string.Empty;
        var apiKey = Environment.GetEnvironmentVariable("WAZUH_API_KEY") ?? string.Empty;
        var alertsEndpoint = Environment.GetEnvironmentVariable("WAZUH_ALERTS_ENDPOINT") ?? "/alerts";
        var ackEndpoint = Environment.GetEnvironmentVariable("WAZUH_ACK_ENDPOINT");
        var headerName = Environment.GetEnvironmentVariable("WAZUH_API_KEY_HEADER") ?? "Authorization";
        var prefix = Environment.GetEnvironmentVariable("WAZUH_API_KEY_PREFIX") ?? "Bearer";
        var limitParam = Environment.GetEnvironmentVariable("WAZUH_LIMIT_PARAM") ?? "limit";
        var sinceParam = Environment.GetEnvironmentVariable("WAZUH_SINCE_PARAM") ?? "from";
        var cursorParam = Environment.GetEnvironmentVariable("WAZUH_CURSOR_PARAM") ?? "cursor";
        var timeoutRaw = Environment.GetEnvironmentVariable("WAZUH_TIMEOUT_SECONDS");
        var timeout = 30;
        if (int.TryParse(timeoutRaw, out var parsed))
            timeout = parsed;

        return new WazuhApiOptions(
            BaseUrl: baseUrl,
            ApiKey: apiKey,
            AlertsEndpoint: alertsEndpoint,
            AckEndpointTemplate: ackEndpoint,
            ApiKeyHeaderName: headerName,
            ApiKeyPrefix: prefix,
            LimitParamName: limitParam,
            SinceParamName: sinceParam,
            CursorParamName: cursorParam,
            TimeoutSeconds: timeout);
    }
}
