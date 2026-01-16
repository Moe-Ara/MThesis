using System.Collections.Generic;
using System.Linq;

namespace Core.Planning;

/// <summary>
/// Builds rollback actions for reversible steps.
/// </summary>
public sealed class BasicRollbackBuilder : IRollbackBuilder
{
    private static readonly Dictionary<ActionType, ActionType> RollbackMap = new()
    {
        [ActionType.BlockIp] = ActionType.UnblockIp,
        [ActionType.IsolateHost] = ActionType.UnisolateHost,
        [ActionType.DisableUser] = ActionType.EnableUser
    };

    public IReadOnlyList<PlannedAction> BuildRollback(IReadOnlyList<PlannedAction> actions, ActionCatalog catalog)
    {
        var rollbacks = new List<PlannedAction>();

        foreach (var action in actions.Reverse())
        {
            if (!action.Reversible)
                continue;

            if (!RollbackMap.TryGetValue(action.Type, out var rollbackType))
                continue;

            if (!catalog.TryGet(rollbackType, out var def))
                continue;
            rollbacks.Add(new PlannedAction(
                ActionId: ActionIdFactory.Create(rollbackType, action.Parameters),
                Type: rollbackType,
                Risk: def.DefaultRisk,
                ExpectedImpact: def.DefaultImpact,
                Reversible: def.SupportsRollback,
                Duration: null,
                Parameters: action.Parameters,
                Rationale: $"Rollback for {action.Type}"
            ));
        }

        return rollbacks;
    }
}
