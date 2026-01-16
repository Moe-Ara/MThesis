using Core.Policy;

namespace Core.CaseManagement;

public interface ICaseManager
{
    CaseRecord OpenOrUpdate(ThreatAssessment assessment, DecisionPlan plan, PolicyDecision decision);
    void AddEvidence(string caseId, EvidenceItem item);
    void Close(string caseId, CaseStatus status);
}
