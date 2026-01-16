namespace Core.Execution;

public sealed record FirewallApiOptions(
    string BaseUrl,
    string? ApiKey,
    int TimeoutSeconds
);
