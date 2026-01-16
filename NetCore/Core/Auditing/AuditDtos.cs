using System;
using System.Collections.Generic;

namespace Core.Auditing;

public sealed record AuditEntry(
    string EntryId,
    DateTimeOffset TimestampUtc,
    string CorrelationId,
    string Component,
    string EventType,
    string Message,
    IReadOnlyDictionary<string, string>? Data = null
);

public sealed record AuditQuery(
    string? CorrelationId = null,
    string? CaseId = null,
    DateTimeOffset? FromUtc = null,
    DateTimeOffset? ToUtc = null
);

public sealed record AuditReport(
    string ReportId,
    DateTimeOffset GeneratedAtUtc,
    AuditQuery Query,
    IReadOnlyList<AuditEntry> Entries,
    IReadOnlyList<string> Summary
);
