using System;
using Core.Interfaces;

namespace Core.Planning;

public sealed class HttpPlannerAdapter : IPlanner
{
    private readonly HttpPlannerClient _client;
    private readonly IPlanner? _fallback;

    public HttpPlannerAdapter(HttpPlannerClient client, IPlanner? fallback = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _fallback = fallback;
    }

    public DecisionPlan Plan(EnrichedAlert alert, ThreatAssessment assessment, PlanningContext ctx)
    {
        var plan = _client.Plan(alert, assessment, ctx);
        if (plan is not null)
            return plan;

        if (_fallback is not null)
            return _fallback.Plan(alert, assessment, ctx);

        throw new InvalidOperationException("Planner API returned no plan and no fallback was configured.");
    }
}
