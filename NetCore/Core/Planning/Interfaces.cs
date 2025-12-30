using System.Collections.Generic;

namespace Core.Planning;

/// <summary>
/// Selects the response strategy for a given alert and assessment.
/// </summary>
public interface IStrategySelector
{
    PlanStrategy Select(EnrichedAlert alert, ThreatAssessment assessment);
}

/// <summary>
/// Selects ordered actions for a strategy using available entities.
/// </summary>
public interface IActionSelector
{
    IReadOnlyList<PlannedAction> SelectActions(
        EnrichedAlert alert,
        ThreatAssessment assessment,
        PlanStrategy strategy,
        ActionCatalog catalog);
}

/// <summary>
/// Estimates risk and impact for actions.
/// </summary>
public interface IRiskEstimator
{
    PlannedAction Estimate(PlannedAction action, EnrichedAlert alert, ThreatAssessment assessment, ActionCatalog catalog);
}

/// <summary>
/// Builds rollback steps for reversible actions.
/// </summary>
public interface IRollbackBuilder
{
    IReadOnlyList<PlannedAction> BuildRollback(IReadOnlyList<PlannedAction> actions, ActionCatalog catalog);
}

/// <summary>
/// Optional action normalization or de-duplication step.
/// </summary>
public interface IActionNormalizer
{
    IReadOnlyList<PlannedAction> Normalize(IReadOnlyList<PlannedAction> actions);
}
