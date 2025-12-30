using System.Text.Json;

public sealed class RawAlert
{
    public string AlertId { get; init; } = default!;
    public string SiemName { get; init; } = default!;
    public DateTimeOffset TimestampUtc { get; init; }

    // The untouched SIEM payload
    public JsonElement Payload { get; init; }

    // Optional, best-effort metadata
    public string? RuleName { get; init; }
    public int? OriginalSeverity { get; init; }
    public string? AlertType { get; init; }
}