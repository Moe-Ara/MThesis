using System.Collections.Generic;
using System.Linq;

namespace Core.Planning;

/// <summary>
/// Default action normalizer that enforces deterministic ordering and de-duplication.
/// </summary>
public sealed class BasicActionNormalizer : IActionNormalizer
{
    public IReadOnlyList<PlannedAction> Normalize(IReadOnlyList<PlannedAction> actions)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var result = new List<PlannedAction>();

        foreach (var action in actions)
        {
            var signature = ActionIdFactory.BuildSignature(action.Type, action.Parameters);
            if (seen.Add(signature))
                result.Add(action);
        }

        return result;
    }
}
