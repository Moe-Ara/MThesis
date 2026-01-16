using System.Threading;
using System.Threading.Tasks;

namespace Core.Execution;

public sealed class HostIsolationExecutor : IActionExecutor
{
    public string Name => "HostIsolationExecutor";

    public bool CanExecute(ActionType type)
        => type is ActionType.IsolateHost or ActionType.UnisolateHost;

    public Task<FeasibilityResult> CheckAsync(PlannedAction action, ExecutionContext ctx, CancellationToken ct)
    {
        if (!HasHost(action))
            return Task.FromResult(new FeasibilityResult(false, "Missing required parameter 'hostname' or 'host_id'."));

        return Task.FromResult(new FeasibilityResult(true, "Ready"));
    }

    public Task<ExecutionOutcome> ExecuteAsync(PlannedAction action, ExecutionContext ctx, CancellationToken ct)
    {
        if (!HasHost(action))
            return Task.FromResult(new ExecutionOutcome(false, "Missing required parameter 'hostname' or 'host_id'."));

        var verb = action.Type == ActionType.IsolateHost ? "isolated" : "unisolate";
        var reference = $"HOST-{action.ActionId}";
        return Task.FromResult(new ExecutionOutcome(true, $"Host {verb} (stub).", reference));
    }

    private static bool HasHost(PlannedAction action)
        => HasValue(action, "hostname") || HasValue(action, "host_id");

    private static bool HasValue(PlannedAction action, string key)
        => action.Parameters.TryGetValue(key, out var value) &&
           !string.IsNullOrWhiteSpace(value);
}
