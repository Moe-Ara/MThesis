namespace Core.Execution;

public sealed record TicketingApiOptions(
    string BaseUrl,
    string? ApiKey,
    string Endpoint = "/v1/tickets",
    string ApiKeyHeaderName = "Authorization",
    string ApiKeyPrefix = "Bearer",
    int TimeoutSeconds = 30
);
