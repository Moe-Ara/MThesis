namespace Core.Planning;

/// <summary>
/// Default strategy selector based on confidence, severity, criticality, and privilege.
/// </summary>
public sealed class BasicStrategySelector : IStrategySelector
{
    public PlanStrategy Select(EnrichedAlert alert, ThreatAssessment assessment)
    {
        var confidence = assessment.Confidence;
        var severity = assessment.Severity;
        var criticality = alert.Context.Asset?.Criticality ?? 0;
        var privileged = alert.Context.Identity?.Privileged ?? false;

        if (confidence < 0.3)
            return PlanStrategy.ObserveMore;

        if ((criticality >= 4 || privileged) && confidence < 0.85)
            return PlanStrategy.EscalateToHuman;

        if (confidence >= 0.85 && severity >= 70)
            return PlanStrategy.ContainAndCollect;

        if (confidence >= 0.6 && severity >= 50)
            return PlanStrategy.Contain;

        return PlanStrategy.NotifyOnly;
    }
}
