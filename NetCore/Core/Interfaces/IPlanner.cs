namespace Core.Interfaces;

public interface IPlanner
{
    DecisionPlan Plan(EnrichedAlert alert, ThreatAssessment assessment, PlanningContext ctx);
}