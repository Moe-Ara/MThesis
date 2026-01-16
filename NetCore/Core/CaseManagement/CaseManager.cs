using System;
using System.Collections.Generic;
using System.Linq;
using Core.Policy;

namespace Core.CaseManagement;

public sealed class CaseManager : ICaseManager
{
    private readonly Dictionary<string, CaseRecord> _cases = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _planToCase = new(StringComparer.Ordinal);
    private readonly object _lock = new();

    public CaseRecord OpenOrUpdate(ThreatAssessment assessment, DecisionPlan plan, PolicyDecision decision)
    {
        if (assessment is null) throw new ArgumentNullException(nameof(assessment));
        if (plan is null) throw new ArgumentNullException(nameof(plan));
        if (decision is null) throw new ArgumentNullException(nameof(decision));

        lock (_lock)
        {
            if (!_planToCase.TryGetValue(plan.PlanId, out var caseId))
            {
                caseId = Guid.NewGuid().ToString("N");
                _planToCase[plan.PlanId] = caseId;
            }

            var now = DateTimeOffset.UtcNow;
            var summary = BuildSummary(plan, decision, assessment);

            if (!_cases.TryGetValue(caseId, out var existing))
            {
                var created = new CaseRecord(
                    CaseId: caseId,
                    PlanId: plan.PlanId,
                    Summary: summary,
                    Status: CaseStatus.Open,
                    CreatedAtUtc: now,
                    UpdatedAtUtc: now,
                    Evidence: new List<EvidenceItem>());

                _cases[caseId] = created;
                return created;
            }

            var updated = existing with
            {
                Summary = summary,
                UpdatedAtUtc = now
            };

            _cases[caseId] = updated;
            return updated;
        }
    }

    public void AddEvidence(string caseId, EvidenceItem item)
    {
        if (string.IsNullOrWhiteSpace(caseId))
            throw new ArgumentException("CaseId is required.", nameof(caseId));
        if (item is null) throw new ArgumentNullException(nameof(item));

        lock (_lock)
        {
            if (!_cases.TryGetValue(caseId, out var record))
                return;

            var updated = record with
            {
                Evidence = record.Evidence.Concat(new[] { item }).ToList(),
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };

            _cases[caseId] = updated;
        }
    }

    public void Close(string caseId, CaseStatus status)
    {
        if (string.IsNullOrWhiteSpace(caseId))
            throw new ArgumentException("CaseId is required.", nameof(caseId));

        if (status is not (CaseStatus.Closed or CaseStatus.FalsePositive))
            throw new ArgumentException("Close status must be Closed or FalsePositive.", nameof(status));

        lock (_lock)
        {
            if (!_cases.TryGetValue(caseId, out var record))
                return;

            var updated = record with
            {
                Status = status,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };

            _cases[caseId] = updated;
        }
    }

    private static string BuildSummary(DecisionPlan plan, PolicyDecision decision, ThreatAssessment assessment)
    {
        return $"{plan.Summary} | " +
               $"Approved={decision.Approved.Count}, Pending={decision.PendingApproval.Count}, Denied={decision.Denied.Count} | " +
               $"Severity={assessment.Severity}, Confidence={assessment.Confidence:0.00}";
    }
}
