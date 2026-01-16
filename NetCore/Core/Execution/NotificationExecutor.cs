using System.Threading;
using System.Threading.Tasks;

namespace Core.Execution;

public sealed class NotificationExecutor : IActionExecutor
{
    public string Name => "NotificationExecutor";

    public bool CanExecute(ActionType type) => type == ActionType.Notify;

    public Task<FeasibilityResult> CheckAsync(PlannedAction action, ExecutionContext ctx, CancellationToken ct)
        => Task.FromResult(new FeasibilityResult(true, "Ready"));

    public Task<ExecutionOutcome> ExecuteAsync(PlannedAction action, ExecutionContext ctx, CancellationToken ct)
    {
        var reference = $"NOTIFY-{action.ActionId}";
        return Task.FromResult(new ExecutionOutcome(true, "Notification sent (stub).", reference));
    }
}
