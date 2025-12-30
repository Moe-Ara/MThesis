using System;
using System.Collections.Generic;
using System.Linq;
using Core.Interfaces;

namespace Core.Planning;

/// <summary>
/// Default planner that composes strategy/action/risk/rollback subcomponents.
/// Produces a deterministic, policy-friendly DecisionPlan.
/// </summary>
public sealed class Planner : IPlanner
{
    private readonly IStrategySelector _strategySelector;
    private readonly IActionSelector _actionSelector;
    private readonly IRiskEstimator _riskEstimator;
    private readonly IRollbackBuilder _rollbackBuilder;
    private readonly IActionNormalizer _normalizer;
    private readonly IActionSanitizer _sanitizer;
    private readonly ActionCatalog _catalog;

    public Planner(
        ActionCatalog catalog,
        IStrategySelector strategySelector,
        IActionSelector actionSelector,
        IRiskEstimator riskEstimator,
        IRollbackBuilder rollbackBuilder,
        IActionNormalizer? normalizer = null,
        IActionSanitizer? sanitizer = null)
    {
        _catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
        _strategySelector = strategySelector ?? throw new ArgumentNullException(nameof(strategySelector));
        _actionSelector = actionSelector ?? throw new ArgumentNullException(nameof(actionSelector));
        _riskEstimator = riskEstimator ?? throw new ArgumentNullException(nameof(riskEstimator));
        _rollbackBuilder = rollbackBuilder ?? throw new ArgumentNullException(nameof(rollbackBuilder));
        _normalizer = normalizer ?? new BasicActionNormalizer();
        _sanitizer = sanitizer ?? new BasicActionSanitizer();
    }

    public DecisionPlan Plan(EnrichedAlert alert, ThreatAssessment assessment, PlanningContext ctx)
    {
        if (alert is null) throw new ArgumentNullException(nameof(alert));
        if (assessment is null) throw new ArgumentNullException(nameof(assessment));
        if (ctx is null) throw new ArgumentNullException(nameof(ctx));

        // 1) Choose strategy
        var strategy = _strategySelector.Select(alert, assessment);

        // 2) Select candidate actions
        var rawActions = _actionSelector
            .SelectActions(alert, assessment, strategy, _catalog)
            .ToList();

        // 3) Estimate risk/impact and apply catalog defaults
        var estimated = rawActions
            .Select(a => _riskEstimator.Estimate(a, alert, assessment, _catalog))
            .Select(a => ApplyCatalogDefaults(a))
            .ToList();

        // 4) Sanitize (drop invalid / missing-required-params actions)
        var sanitized = _sanitizer.Sanitize(estimated, _catalog).ToList();

        // 5) Normalize/dedupe/ordering
        var normalized = _normalizer.Normalize(sanitized).ToList();
        normalized = StableOrder(normalized);

        // 6) Rollback
        var rollback = _rollbackBuilder.BuildRollback(normalized, _catalog)
            .Where(a => _catalog.Get(a.Type).SupportsRollback) // final guard
            .ToList();

        // 7) Plan metadata
        var summary = $"Strategy={strategy}, Severity={assessment.Severity}, Confidence={assessment.Confidence:0.00}";
        var rationale = BuildRationale(alert, assessment, strategy, ctx);

        return new DecisionPlan(
            PlanId: Guid.NewGuid().ToString("N"),
            Strategy: strategy,
            Priority: ComputePriority(alert, assessment),
            Summary: summary,
            Actions: normalized,
            RollbackActions: rollback,
            Rationale: rationale,
            Tags: BuildTags(alert, assessment, ctx)
        );
    }

    private PlannedAction ApplyCatalogDefaults(PlannedAction action)
    {
        var def = _catalog.Get(action.Type);

        // Fill missing values in a policy-friendly way
        var risk = action.Risk <= 0 ? def.DefaultRisk : action.Risk;
        var impact = action.ExpectedImpact <= 0 ? def.DefaultImpact : action.ExpectedImpact;

        return action with
        {
            Risk = Math.Clamp(risk, 0, 100),
            ExpectedImpact = Math.Clamp(impact, 0, 100),
            Reversible = def.SupportsRollback
        };
    }

    private static List<PlannedAction> StableOrder(List<PlannedAction> actions)
    {
        // Deterministic ordering for tests and reproducibility:
        // risk asc (least risky first), then impact asc, then type, then id.
        return actions
            .OrderBy(a => a.Risk)
            .ThenBy(a => a.ExpectedImpact)
            .ThenBy(a => a.Type)
            .ThenBy(a => a.ActionId, StringComparer.Ordinal)
            .ToList();
    }

    private static int ComputePriority(EnrichedAlert alert, ThreatAssessment assessment)
    {
        var criticality = alert.Context.Asset?.Criticality ?? 0;
        var baseScore = assessment.Severity + (criticality * 10);
        var boosted = baseScore + (int)(assessment.Confidence * 20);
        return Math.Clamp(boosted, 0, 100);
    }

    private static IReadOnlyList<string> BuildRationale(
        EnrichedAlert alert,
        ThreatAssessment assessment,
        PlanStrategy strategy,
        PlanningContext ctx)
    {
        var notes = new List<string>
        {
            $"Selected strategy {strategy} based on confidence {assessment.Confidence:0.00} and severity {assessment.Severity}.",
            $"Asset criticality: {alert.Context.Asset?.Criticality ?? 0}; privileged identity: {alert.Context.Identity?.Privileged ?? false}.",
            $"Environment: {ctx.Environment}; DryRun: {ctx.DryRun}."
        };

        if (!string.IsNullOrWhiteSpace(assessment.Hypothesis))
            notes.Add($"Hypothesis: {assessment.Hypothesis}");

        if (assessment.Evidence is { Count: > 0 })
            notes.Add($"Evidence count: {assessment.Evidence.Count}");

        return notes;
    }

    private static IReadOnlyDictionary<string, string> BuildTags(
        EnrichedAlert alert,
        ThreatAssessment assessment,
        PlanningContext ctx)
    {
        return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["siem"] = alert.Base.SourceSiem,
            ["alert_id"] = alert.Base.AlertId,
            ["environment"] = ctx.Environment,
            ["severity"] = assessment.Severity.ToString(),
            ["confidence"] = assessment.Confidence.ToString("0.00")
        };
    }
}
