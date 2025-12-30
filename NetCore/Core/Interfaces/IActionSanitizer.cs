namespace Core.Interfaces;

/// <summary>
/// Filters invalid actions before execution or policy evaluation.
/// </summary>
public interface IActionSanitizer
{
    /// <summary>
    /// Remove actions that are missing required parameters.
    /// </summary>
    IEnumerable<PlannedAction> Sanitize(IEnumerable<PlannedAction> actions, ActionCatalog catalog);
}
