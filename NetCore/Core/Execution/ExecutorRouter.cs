namespace Core.Execution;

public sealed class ExecutorRouter : IExecutorRouter
{
    private readonly IReadOnlyList<IActionExecutor> _executors;

    public ExecutorRouter(IEnumerable<IActionExecutor> executors)
    {
        _executors = (executors ?? Enumerable.Empty<IActionExecutor>()).ToList();
    }

    public IActionExecutor? Resolve(ActionType type)
        => _executors.FirstOrDefault(executor => executor.CanExecute(type));
}
