using System;
using System.Collections.Generic;

namespace Core.CaseManagement;

public enum CaseStatus
{
    Open,
    InProgress,
    Closed,
    FalsePositive
}

public sealed record EvidenceItem(
    string EvidenceId,
    string Description,
    DateTimeOffset TimestampUtc
);

public sealed record CaseRecord(
    string CaseId,
    string PlanId,
    string Summary,
    CaseStatus Status,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    IReadOnlyList<EvidenceItem> Evidence
);
