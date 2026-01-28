namespace Core.Execution;

public sealed record NotificationApiOptions(
    string BaseUrl,
    string? ApiKey,
    string Endpoint = "/v1/notify",
    string ApiKeyHeaderName = "Authorization",
    string ApiKeyPrefix = "Bearer",
    int TimeoutSeconds = 30
);
