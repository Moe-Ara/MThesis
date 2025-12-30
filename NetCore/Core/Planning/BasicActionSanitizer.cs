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
            var required = catalog.Get(a.Type).RequiredParameters;
            if (required is null || required.Count == 0)
            {
                yield return a;
                continue;
            }

            var ok = required switch
            {
                [ "username", "user_id" ] => HasAny(a, "username", "user_id"),
                [ "hostname", "host_id" ] => HasAny(a, "hostname", "host_id"),
                _ => HasAll(a, required)
            };

            if (ok) yield return a;
        }
    }

    private static bool HasAny(PlannedAction action, params string[] keys)
        => keys.Any(key => action.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value));

    private static bool HasAll(PlannedAction action, IEnumerable<string> keys)
        => keys.All(key => action.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value));
}
