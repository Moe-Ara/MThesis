using System;

namespace Core.Planning;

public sealed record HttpPlannerOptions(
    string BaseUrl,
    string? ApiKey,
    string Endpoint = "/v1/plan",
    string ApiKeyHeaderName = "Authorization",
    string ApiKeyPrefix = "Bearer",
    int TimeoutSeconds = 30)
{
    public static HttpPlannerOptions FromEnvironment()
    {
        var baseUrl = Environment.GetEnvironmentVariable("PLANNER_API_BASEURL") ?? string.Empty;
        var apiKey = Environment.GetEnvironmentVariable("PLANNER_API_KEY");
        var endpoint = Environment.GetEnvironmentVariable("PLANNER_API_ENDPOINT") ?? "/v1/plan";
        var header = Environment.GetEnvironmentVariable("PLANNER_API_KEY_HEADER") ?? "Authorization";
        var prefix = Environment.GetEnvironmentVariable("PLANNER_API_KEY_PREFIX") ?? "Bearer";
        var timeoutRaw = Environment.GetEnvironmentVariable("PLANNER_API_TIMEOUT_SECONDS");
        var timeout = 30;
        if (int.TryParse(timeoutRaw, out var parsed))
            timeout = parsed;

        return new HttpPlannerOptions(baseUrl, apiKey, endpoint, header, prefix, timeout);
    }
}
