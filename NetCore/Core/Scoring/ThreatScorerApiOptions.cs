namespace Core.Scoring;

public sealed record ThreatScorerApiOptions(
    string BaseUrl,
    string? ApiKey,
    int TimeoutSeconds
);
