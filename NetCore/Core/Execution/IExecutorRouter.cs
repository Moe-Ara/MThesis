namespace Core.Execution;

public interface IExecutorRouter
{
    IActionExecutor? Resolve(ActionType type);
}
