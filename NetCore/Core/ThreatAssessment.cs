using System.Collections.Generic;

/// <summary>
/// Output of the ML scoring stage used by the planner.
/// </summary>
public sealed record ThreatAssessment(
    double Confidence,
    int Severity,
    string Hypothesis,
    IReadOnlyList<string> Evidence,
    IReadOnlyList<ProposedAction>? RecommendedActions = null
);

/// <summary>
/// Optional recommended action from scoring stage.
/// </summary>
public sealed record ProposedAction(
    ActionType Type,
    IReadOnlyDictionary<string, string> Parameters,
    string? Rationale = null
);
