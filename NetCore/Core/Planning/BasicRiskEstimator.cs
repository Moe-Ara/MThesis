namespace Core.Planning;

/// <summary>
/// Default risk/impact estimator using catalog defaults and alert context.
/// </summary>
public sealed class BasicRiskEstimator : IRiskEstimator
{
    public PlannedAction Estimate(
        PlannedAction action,
        EnrichedAlert alert,
        ThreatAssessment assessment,
        ActionCatalog catalog)
    {
        var def = catalog.Get(action.Type);
        var criticality = alert.Context.Asset?.Criticality ?? 0;
        var privileged = alert.Context.Identity?.Privileged ?? false;
        var confidence = assessment.Confidence;

        var risk = def.DefaultRisk + (int)((1.0 - confidence) * 30);
        var impact = def.DefaultImpact + (criticality * 5);

        if (privileged)
        {
            risk += 10;
            impact += 10;
        }

        risk = Clamp(risk, 0, 100);
        impact = Clamp(impact, 0, 100);

        return action with
        {
            Risk = risk,
            ExpectedImpact = impact,
            Reversible = def.SupportsRollback
        };
    }

    private static int Clamp(int value, int min, int max)
        => value < min ? min : value > max ? max : value;
}
