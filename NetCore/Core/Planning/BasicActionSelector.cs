using System.Collections.Generic;
using System.Linq;

namespace Core.Planning;

/// <summary>
/// Default action selector that prefers least destructive actions first.
/// </summary>
public sealed class BasicActionSelector : IActionSelector
{
    private static readonly ActionType[] ActionOrder =
    [
        ActionType.Notify,
        ActionType.OpenTicket,
        ActionType.BlockIp,
        ActionType.DisableUser,
        ActionType.IsolateHost,
        ActionType.CollectForensics
    ];

    public IReadOnlyList<PlannedAction> SelectActions(
        EnrichedAlert alert,
        ThreatAssessment assessment,
        PlanStrategy strategy,
        ActionCatalog catalog)
    {
        var actions = new List<PlannedAction>();

        switch (strategy)
        {
            case PlanStrategy.ObserveMore:
                actions.Add(Build(ActionType.OpenTicket, "Create a tracking ticket.", new Dictionary<string, string>()));
                break;
            case PlanStrategy.NotifyOnly:
                actions.Add(Build(ActionType.Notify, "Notify analysts.", new Dictionary<string, string>()));
                actions.Add(Build(ActionType.OpenTicket, "Create a tracking ticket.", new Dictionary<string, string>()));
                break;
            case PlanStrategy.Contain:
                AddContainment(alert, actions);
                actions.Add(Build(ActionType.OpenTicket, "Create a tracking ticket.", new Dictionary<string, string>()));
                break;
            case PlanStrategy.ContainAndCollect:
                AddContainment(alert, actions);
                actions.Add(Build(ActionType.CollectForensics, "Collect forensic artifacts.", new Dictionary<string, string>()));
                actions.Add(Build(ActionType.OpenTicket, "Create a tracking ticket.", new Dictionary<string, string>()));
                break;
            case PlanStrategy.EscalateToHuman:
                actions.Add(Build(ActionType.Notify, "Escalate to human analyst.", new Dictionary<string, string>()));
                actions.Add(Build(ActionType.OpenTicket, "Create a tracking ticket.", new Dictionary<string, string>()));
                break;
        }

        // Merge optional recommended actions without breaking guardrails.
        if (assessment.RecommendedActions is not null)
        {
            foreach (var rec in assessment.RecommendedActions)
            {
                if (!HasRequiredEntities(rec.Type, alert))
                    continue;

                actions.Add(Build(rec.Type, rec.Rationale ?? "Recommended action.", rec.Parameters));
            }
        }

        var ordered = actions
            .Where(a => HasRequiredEntities(a.Type, alert))
            .OrderBy(a => ActionOrderIndex(a.Type))
            .ToList();

        return ordered;
    }

    private static void AddContainment(EnrichedAlert alert, List<PlannedAction> actions)
    {
        var entities = alert.Base.Entities;
        if (!string.IsNullOrWhiteSpace(entities.SrcIp))
        {
            actions.Add(Build(ActionType.BlockIp, "Block suspicious source IP.",
                new Dictionary<string, string> { ["src_ip"] = entities.SrcIp }));
        }

        if (!string.IsNullOrWhiteSpace(entities.Username) || !string.IsNullOrWhiteSpace(entities.UserId))
        {
            actions.Add(Build(ActionType.DisableUser, "Disable user account.",
                BuildUserParams(entities)));
        }

        if (!string.IsNullOrWhiteSpace(entities.Hostname) || !string.IsNullOrWhiteSpace(entities.HostId))
        {
            actions.Add(Build(ActionType.IsolateHost, "Isolate host.",
                BuildHostParams(entities)));
        }
    }

    private static PlannedAction Build(ActionType type, string rationale, IReadOnlyDictionary<string, string> parameters)
        => new(
            ActionId: ActionIdFactory.Create(type, parameters),
            Type: type,
            Risk: 0,
            ExpectedImpact: 0,
            Reversible: false,
            Duration: null,
            Parameters: new Dictionary<string, string>(parameters),
            Rationale: rationale);

    private static Dictionary<string, string> BuildUserParams(Entities entities)
    {
        var parameters = new Dictionary<string, string>();
        if (!string.IsNullOrWhiteSpace(entities.Username))
            parameters["username"] = entities.Username!;
        if (!string.IsNullOrWhiteSpace(entities.UserId))
            parameters["user_id"] = entities.UserId!;
        return parameters;
    }

    private static Dictionary<string, string> BuildHostParams(Entities entities)
    {
        var parameters = new Dictionary<string, string>();
        if (!string.IsNullOrWhiteSpace(entities.Hostname))
            parameters["hostname"] = entities.Hostname!;
        if (!string.IsNullOrWhiteSpace(entities.HostId))
            parameters["host_id"] = entities.HostId!;
        return parameters;
    }

    private static int ActionOrderIndex(ActionType type)
    {
        var index = System.Array.IndexOf(ActionOrder, type);
        return index == -1 ? int.MaxValue : index;
    }

    private static bool HasRequiredEntities(ActionType type, EnrichedAlert alert)
    {
        var e = alert.Base.Entities;
        return type switch
        {
            ActionType.BlockIp => !string.IsNullOrWhiteSpace(e.SrcIp),
            ActionType.IsolateHost => !string.IsNullOrWhiteSpace(e.Hostname) || !string.IsNullOrWhiteSpace(e.HostId),
            ActionType.DisableUser => !string.IsNullOrWhiteSpace(e.Username) || !string.IsNullOrWhiteSpace(e.UserId),
            ActionType.UnblockIp => !string.IsNullOrWhiteSpace(e.SrcIp),
            ActionType.UnisolateHost => !string.IsNullOrWhiteSpace(e.Hostname) || !string.IsNullOrWhiteSpace(e.HostId),
            ActionType.EnableUser => !string.IsNullOrWhiteSpace(e.Username) || !string.IsNullOrWhiteSpace(e.UserId),
            _ => true
        };
    }
}
