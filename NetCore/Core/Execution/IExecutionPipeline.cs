using System.Threading;
using System.Threading.Tasks;
using Core.Policy;

namespace Core.Execution;

public interface IExecutionPipeline
{
    Task<ExecutionReport> ExecuteAsync(
        EnrichedAlert alert,
        ThreatAssessment assessment,
        DecisionPlan plan,
        PolicyDecision policy,
        ExecutionContext ctx,
        CancellationToken ct);

    Task<ExecutionReport> ExecuteAsync(
        DecisionPlan plan,
        PolicyDecision policy,
        ExecutionContext ctx,
        CancellationToken ct);
}
