using System;
using Core.Policy;

namespace Core.CaseManagement;

public sealed class NullCaseManager : ICaseManager
{
    public CaseRecord OpenOrUpdate(ThreatAssessment assessment, DecisionPlan plan, PolicyDecision decision)
        => new(
            CaseId: "null",
            PlanId: plan.PlanId,
            Summary: "No-op case manager.",
            Status: CaseStatus.Open,
            CreatedAtUtc: DateTimeOffset.UtcNow,
            UpdatedAtUtc: DateTimeOffset.UtcNow,
            Evidence: Array.Empty<EvidenceItem>());

    public void AddEvidence(string caseId, EvidenceItem item)
    {
    }

    public void Close(string caseId, CaseStatus status)
    {
    }
}
