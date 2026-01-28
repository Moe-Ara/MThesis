using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Core.Policy;

/// <summary>
/// Configuration for policy gating thresholds and hard constraints.
/// </summary>
public sealed record PolicyConfig(
    float MinConfidenceForAutonomy,
    int RiskApprovalThreshold,
    int ImpactApprovalThreshold,
    int MaxActionsPerPlan,
    int CriticalAssetThreshold,
    HashSet<ActionType> SafeLowConfidenceActions,
    HashSet<ActionType> RequireApprovalInProd,
    HashSet<ActionType> RequireApprovalOnPrivilegedIdentities,
    HashSet<ActionType> RequireApprovalOnCriticalAssets,
    HashSet<ActionType> ForbidActionsOnPrivilegedIdentities,
    HashSet<ActionType> ForbidActionsOnCriticalAssets,
    Dictionary<string, HashSet<ActionType>> ForbiddenActionsByEnvironment)
{
    public static PolicyConfig Default => new(
        MinConfidenceForAutonomy: 0.60f,
        RiskApprovalThreshold: 70,
        ImpactApprovalThreshold: 70,
        MaxActionsPerPlan: 6,
        CriticalAssetThreshold: 4,

        SafeLowConfidenceActions: new HashSet<ActionType>
        {
            ActionType.OpenTicket,
            ActionType.Notify
        },

        RequireApprovalInProd: new HashSet<ActionType>
        {
            ActionType.DisableUser,
            ActionType.IsolateHost,
            ActionType.QuarantineFile,
            ActionType.KillProcess
        },

        RequireApprovalOnPrivilegedIdentities: new HashSet<ActionType>
        {
            ActionType.DisableUser
        },

        RequireApprovalOnCriticalAssets: new HashSet<ActionType>
        {
            ActionType.IsolateHost,
            ActionType.DisableUser
        },

        ForbidActionsOnPrivilegedIdentities: new HashSet<ActionType>
        {
            ActionType.DisableUser
        },

        ForbidActionsOnCriticalAssets: new HashSet<ActionType>
        {
            ActionType.KillProcess,
            ActionType.QuarantineFile
        },

        ForbiddenActionsByEnvironment: new Dictionary<string, HashSet<ActionType>>(StringComparer.OrdinalIgnoreCase)
        {
            ["prod"] = new HashSet<ActionType>
            {
                // add forbidden prod actions here if needed
            }
        }
    );

    public static PolicyConfig LoadFromJson(string path, PolicyConfig? fallback = null)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Path is required.", nameof(path));

        if (!File.Exists(path))
            return fallback ?? Default;

        var json = File.ReadAllText(path);
        if (string.IsNullOrWhiteSpace(json))
            return fallback ?? Default;

        var dto = JsonSerializer.Deserialize<PolicyConfigDto>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        if (dto is null)
            return fallback ?? Default;

        var result = new PolicyConfig(
            MinConfidenceForAutonomy: dto.MinConfidenceForAutonomy ?? Default.MinConfidenceForAutonomy,
            RiskApprovalThreshold: dto.RiskApprovalThreshold ?? Default.RiskApprovalThreshold,
            ImpactApprovalThreshold: dto.ImpactApprovalThreshold ?? Default.ImpactApprovalThreshold,
            MaxActionsPerPlan: dto.MaxActionsPerPlan ?? Default.MaxActionsPerPlan,
            CriticalAssetThreshold: dto.CriticalAssetThreshold ?? Default.CriticalAssetThreshold,
            SafeLowConfidenceActions: ToActionSet(dto.SafeLowConfidenceActions, Default.SafeLowConfidenceActions),
            RequireApprovalInProd: ToActionSet(dto.RequireApprovalInProd, Default.RequireApprovalInProd),
            RequireApprovalOnPrivilegedIdentities: ToActionSet(dto.RequireApprovalOnPrivilegedIdentities, Default.RequireApprovalOnPrivilegedIdentities),
            RequireApprovalOnCriticalAssets: ToActionSet(dto.RequireApprovalOnCriticalAssets, Default.RequireApprovalOnCriticalAssets),
            ForbidActionsOnPrivilegedIdentities: ToActionSet(dto.ForbidActionsOnPrivilegedIdentities, Default.ForbidActionsOnPrivilegedIdentities),
            ForbidActionsOnCriticalAssets: ToActionSet(dto.ForbidActionsOnCriticalAssets, Default.ForbidActionsOnCriticalAssets),
            ForbiddenActionsByEnvironment: ToEnvActionMap(dto.ForbiddenActionsByEnvironment, Default.ForbiddenActionsByEnvironment));

        return result;
    }

    private static HashSet<ActionType> ToActionSet(IEnumerable<string>? raw, HashSet<ActionType> fallback)
    {
        if (raw is null)
            return new HashSet<ActionType>(fallback);

        var set = new HashSet<ActionType>();
        foreach (var item in raw)
        {
            if (Enum.TryParse<ActionType>(item, true, out var action))
                set.Add(action);
        }

        return set.Count > 0 ? set : new HashSet<ActionType>(fallback);
    }

    private static Dictionary<string, HashSet<ActionType>> ToEnvActionMap(
        Dictionary<string, List<string>>? raw,
        Dictionary<string, HashSet<ActionType>> fallback)
    {
        if (raw is null)
            return new Dictionary<string, HashSet<ActionType>>(fallback, StringComparer.OrdinalIgnoreCase);

        var map = new Dictionary<string, HashSet<ActionType>>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in raw)
        {
            var set = ToActionSet(kv.Value, new HashSet<ActionType>());
            map[kv.Key] = set;
        }

        return map.Count > 0 ? map : new Dictionary<string, HashSet<ActionType>>(fallback, StringComparer.OrdinalIgnoreCase);
    }

    private sealed record PolicyConfigDto
    {
        public float? MinConfidenceForAutonomy { get; init; }
        public int? RiskApprovalThreshold { get; init; }
        public int? ImpactApprovalThreshold { get; init; }
        public int? MaxActionsPerPlan { get; init; }
        public int? CriticalAssetThreshold { get; init; }
        public List<string>? SafeLowConfidenceActions { get; init; }
        public List<string>? RequireApprovalInProd { get; init; }
        public List<string>? RequireApprovalOnPrivilegedIdentities { get; init; }
        public List<string>? RequireApprovalOnCriticalAssets { get; init; }
        public List<string>? ForbidActionsOnPrivilegedIdentities { get; init; }
        public List<string>? ForbidActionsOnCriticalAssets { get; init; }
        public Dictionary<string, List<string>>? ForbiddenActionsByEnvironment { get; init; }
    }
}
