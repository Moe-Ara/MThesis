using System;
using System.Collections.Generic;

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
}
