using System.Threading;
using System.Threading.Tasks;

namespace Core.Execution;

public sealed class UserAccessExecutor : IActionExecutor
{
    public string Name => "UserAccessExecutor";

    public bool CanExecute(ActionType type)
        => type is ActionType.DisableUser or ActionType.EnableUser;

    public Task<FeasibilityResult> CheckAsync(PlannedAction action, ExecutionContext ctx, CancellationToken ct)
    {
        if (!HasUser(action))
            return Task.FromResult(new FeasibilityResult(false, "Missing required parameter 'username' or 'user_id'."));

        return Task.FromResult(new FeasibilityResult(true, "Ready"));
    }

    public Task<ExecutionOutcome> ExecuteAsync(PlannedAction action, ExecutionContext ctx, CancellationToken ct)
    {
        if (!HasUser(action))
            return Task.FromResult(new ExecutionOutcome(false, "Missing required parameter 'username' or 'user_id'."));

        var verb = action.Type == ActionType.DisableUser ? "disabled" : "enabled";
        var reference = $"USER-{action.ActionId}";
        return Task.FromResult(new ExecutionOutcome(true, $"User {verb} (stub).", reference));
    }

    private static bool HasUser(PlannedAction action)
        => HasValue(action, "username") || HasValue(action, "user_id");

    private static bool HasValue(PlannedAction action, string key)
        => action.Parameters.TryGetValue(key, out var value) &&
           !string.IsNullOrWhiteSpace(value);
}
