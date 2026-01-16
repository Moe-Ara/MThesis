namespace Core.Execution;

public interface IActionExecutor
{
    string Name { get; }
    bool CanExecute(ActionType type);

    Task<FeasibilityResult> CheckAsync(
        PlannedAction action,
        ExecutionContext ctx,
        CancellationToken ct);

    Task<ExecutionOutcome> ExecuteAsync(
        PlannedAction action,
        ExecutionContext ctx,
        CancellationToken ct);
}
