using System;

namespace Core.Planning;

public sealed record HttpPlannerOptions(
    string BaseUrl,
    string? ApiKey,
    string Endpoint = "/v1/plan",
    string ApiKeyHeaderName = "Authorization",
    string ApiKeyPrefix = "Bearer",
    int TimeoutSeconds = 30,
    string? ModelProfile = null)
{
    public static HttpPlannerOptions FromEnvironment(string? baseUrlOverride = null)
    {
        var baseUrl = baseUrlOverride
                      ?? Environment.GetEnvironmentVariable("PLANNER_API_BASEURL")
                      ?? string.Empty;
        var apiKey = Environment.GetEnvironmentVariable("PLANNER_API_KEY");
        var endpoint = Environment.GetEnvironmentVariable("PLANNER_API_ENDPOINT") ?? "/v1/plan";
        var header = Environment.GetEnvironmentVariable("PLANNER_API_KEY_HEADER") ?? "Authorization";
        var prefix = Environment.GetEnvironmentVariable("PLANNER_API_KEY_PREFIX") ?? "Bearer";
        var timeoutRaw = Environment.GetEnvironmentVariable("PLANNER_API_TIMEOUT_SECONDS");
        var timeout = 30;
        if (int.TryParse(timeoutRaw, out var parsed))
            timeout = parsed;

        var modelProfile = Environment.GetEnvironmentVariable("PLANNER_MODEL_PROFILE")
                           ?? Environment.GetEnvironmentVariable("INTEL_MODEL_PROFILE")
                           ?? Environment.GetEnvironmentVariable("INTEL_ACTIVE_PROFILE");
        return new HttpPlannerOptions(baseUrl, apiKey, endpoint, header, prefix, timeout, modelProfile);
    }
}
