using System.Text.Json;

public sealed record NormalizedAlert(
    string AlertId,
    string SourceSiem,
    DateTimeOffset TimestampUtc,
    string? AlertType,
    string? RuleName,
    int Severity, // 0-100 normalized
    Entities Entities,
    JsonElement RawPayload
);

public sealed record Entities(
    string? Hostname,
    string? HostId,
    string? Username,
    string? UserId,
    string? SrcIp,
    string? DstIp,
    string? Domain,
    string? ProcessName,
    string? ProcessPath,
    string? FileHash
);
public sealed record EnrichedAlert(
    NormalizedAlert Base,
    EnrichmentContext Context,
    IReadOnlyList<EnrichmentNote> Provenance
);
public sealed record EnrichmentContext(
    AssetContext? Asset,
    IdentityContext? Identity,
    ThreatIntelContext? ThreatIntel,
    HistoryContext? History,
    IReadOnlyDictionary<string, string>? Tags = null
);
public sealed record AssetContext(
    string AssetId,
    int Criticality,              // e.g. 0–5 or 0–100
    string? Environment = null,   // prod/dev
    IReadOnlyList<string>? Roles = null
);

public sealed record IdentityContext(
    string? UserId,
    bool Privileged,
    string? Department = null,
    IReadOnlyList<string>? Groups = null
);

public sealed record ThreatIntelContext(
    int ReputationScore,          // e.g. -100..100 or 0..100
    IReadOnlyList<string>? Matches = null
);

public sealed record HistoryContext(
    int PastIncidents,
    DateTimeOffset? LastSeenUtc,
    IReadOnlyList<string>? RelatedCaseIds = null
);

public sealed record EnrichmentNote(
    string ProviderName,
    DateTimeOffset TimestampUtc,
    string Summary
);
public sealed record EnrichmentPatch(
    AssetContext? Asset = null,
    IdentityContext? Identity = null,
    ThreatIntelContext? ThreatIntel = null,
    HistoryContext? History = null,
    IReadOnlyDictionary<string, string>? Tags = null,
    EnrichmentNote? Note = null
);
public sealed record ValidationResult(
    bool IsValid,
    IReadOnlyList<string> Errors
);

