using System.Threading;
using System.Threading.Tasks;

namespace Core.Execution;

public sealed class FirewallExecutor : IActionExecutor
{
    public string Name => "FirewallExecutor";

    public bool CanExecute(ActionType type)
        => type is ActionType.BlockIp or ActionType.UnblockIp;

    public Task<FeasibilityResult> CheckAsync(PlannedAction action, ExecutionContext ctx, CancellationToken ct)
    {
        if (!HasSrcIp(action))
            return Task.FromResult(new FeasibilityResult(false, "Missing required parameter 'src_ip'."));

        return Task.FromResult(new FeasibilityResult(true, "Ready"));
    }

    public Task<ExecutionOutcome> ExecuteAsync(PlannedAction action, ExecutionContext ctx, CancellationToken ct)
    {
        if (!HasSrcIp(action))
            return Task.FromResult(new ExecutionOutcome(false, "Missing required parameter 'src_ip'."));

        var verb = action.Type == ActionType.BlockIp ? "blocked" : "unblocked";
        var reference = $"FW-{action.ActionId}";
        return Task.FromResult(new ExecutionOutcome(true, $"IP {verb} (stub).", reference));
    }

    private static bool HasSrcIp(PlannedAction action)
        => action.Parameters.TryGetValue("src_ip", out var value) &&
           !string.IsNullOrWhiteSpace(value);
}
