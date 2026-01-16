using System.Collections.Generic;

namespace Core.Planning;

/// <summary>
/// Provides a default catalog of supported actions.
/// </summary>
public static class ActionCatalogDefaults
{
    /// <summary>
    /// Create the default action catalog.
    /// </summary>
    public static ActionCatalog CreateDefault()
    {
        var items = new Dictionary<ActionType, ActionDefinition>
        {
            [ActionType.BlockIp] = new(ActionType.BlockIp, true, true, 55, 30, new[] { "src_ip" }),
            [ActionType.UnblockIp] = new(ActionType.UnblockIp, false, false, 10, 5, new[] { "src_ip" }),
            [ActionType.IsolateHost] = new(ActionType.IsolateHost, true, true, 70, 60, new[] { "hostname", "host_id" }),
            [ActionType.UnisolateHost] = new(ActionType.UnisolateHost, false, false, 15, 10, new[] { "hostname", "host_id" }),
            [ActionType.DisableUser] = new(ActionType.DisableUser, true, true, 65, 50, new[] { "username", "user_id" }),
            [ActionType.EnableUser] = new(ActionType.EnableUser, false, false, 15, 10, new[] { "username", "user_id" }),
            [ActionType.KillProcess] = new(ActionType.KillProcess, false, true, 85, 85, new[] { "hostId", "hostname", "processName", "pid" }),
            [ActionType.QuarantineFile] = new(ActionType.QuarantineFile, false, true, 85, 85, new[] { "hostId", "fileHash", "filePath" }),
            [ActionType.OpenTicket] = new(ActionType.OpenTicket, false, false, 5, 5),
            [ActionType.Notify] = new(ActionType.Notify, false, false, 5, 5),
            [ActionType.CollectForensics] = new(ActionType.CollectForensics, false, true, 35, 20),
        };

        return new ActionCatalog(items);
    }
}
