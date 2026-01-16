using Core.Interfaces;

namespace Core.Planning;

/// <summary>
/// Drops actions that are missing required parameters or have empty values.
/// This is NOT policy; it's basic action correctness.
/// </summary>
public sealed class BasicActionSanitizer : IActionSanitizer
{
    public IEnumerable<PlannedAction> Sanitize(IEnumerable<PlannedAction> actions, ActionCatalog catalog)
    {
        foreach (var a in actions)
        {
            if (!catalog.TryGet(a.Type, out var def))
                continue;

            if (HasRequiredParameters(a, def))
            {
                yield return a;
            }
        }
    }

    private static bool HasRequiredParameters(PlannedAction action, ActionDefinition def)
    {
        var required = def.RequiredParameters;
        if (required is null || required.Count == 0)
            return true;

        return action.Type switch
        {
            ActionType.KillProcess => HasAny(action, "host_id", "hostId", "hostname") &&
                                      HasAny(action, "process_name", "processName", "pid"),
            ActionType.QuarantineFile => HasAny(action, "host_id", "hostId") &&
                                         HasAny(action, "file_hash", "fileHash", "file_path", "filePath"),
            _ => required switch
            {
                [ "username", "user_id" ] => HasAny(action, "username", "user_id"),
                [ "hostname", "host_id" ] => HasAny(action, "hostname", "host_id"),
                _ => HasAll(action, required)
            }
        };
    }

    private static bool HasAny(PlannedAction action, params string[] keys)
        => keys.Any(key => action.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value));

    private static bool HasAll(PlannedAction action, IEnumerable<string> keys)
        => keys.All(key => action.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value));
}
