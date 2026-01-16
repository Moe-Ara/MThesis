using System.Threading;
using System.Threading.Tasks;

namespace Core.Execution;

public sealed class TicketingExecutor : IActionExecutor
{
    public string Name => "TicketingExecutor";

    public bool CanExecute(ActionType type) => type == ActionType.OpenTicket;

    public Task<FeasibilityResult> CheckAsync(PlannedAction action, ExecutionContext ctx, CancellationToken ct)
        => Task.FromResult(new FeasibilityResult(true, "Ready"));

    public Task<ExecutionOutcome> ExecuteAsync(PlannedAction action, ExecutionContext ctx, CancellationToken ct)
    {
        var reference = $"TICKET-{action.ActionId}";
        return Task.FromResult(new ExecutionOutcome(true, "Ticket created (stub).", reference));
    }
}
